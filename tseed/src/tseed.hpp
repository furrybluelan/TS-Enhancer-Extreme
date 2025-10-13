#pragma once
#include "util.hpp"
#include <argparse/argparse.hpp>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>

struct RootDetectionConfig {
    std::string tseeConfig;
    std::string adbPath;
    std::string dmesgLog;
    std::string typePath;
    std::string multiplePath;
    std::string kernelTypePath;
};

class RootDetector {
private:
    RootDetectionConfig config;
    
    // Flags for kernel tags
    bool kernelsuKtag = false;
    bool apatchKtag = false;
    bool magiskKtag = false;
    
    // Flags for tool tags
    bool kernelsuTag = false;
    bool suckysuTag = false;
    bool apatchTag = false;
    bool magiskTag = false;
    
    std::string rootType;

    // Check if string contains substring (case-sensitive)
    bool fileContains(const std::string& filepath, const std::string& searchStr) {
        std::ifstream file(filepath);
        if (!file.is_open()) return false;
        
        std::string line;
        while (std::getline(file, line)) {
            if (line.find(searchStr) != std::string::npos) {
                file.close();
                return true;
            }
        }
        file.close();
        return false;
    }

    // Check if any of multiple strings exist in file
    bool fileContainsAny(const std::string& filepath, const std::vector<std::string>& searches) {
        for (const auto& search : searches) {
            if (fileContains(filepath, search)) {
                return true;
            }
        }
        return false;
    }

    // Check for KernelSU
    void detectKernelSU() {
        if (fileContains(config.dmesgLog, "KernelSU")) {
            kernelsuKtag = true;
            
            std::string ksuPath = config.adbPath + "/ksu";
            std::string ksudPath = config.adbPath + "/ksud";
            
            if (fs::is_directory(ksuPath) && fs::is_regular_file(ksudPath)) {
                if (fileContains(config.dmesgLog, "KP hook sukisu_kpm")) {
                    suckysuTag = true;
                } else {
                    // Check ksud version
                    std::string versionOutput = executeCommand(config.adbPath + "/ksud -V 2>/dev/null");
                    if (versionOutput.find("zako") != std::string::npos) {
                        suckysuTag = true;
                    } else {
                        kernelsuTag = true;
                    }
                }
            }
        }
    }

    // Check for Magisk
    void detectMagisk() {
        if (fileContainsAny(config.dmesgLog, {"/debug_ramdisk/magisk", "magiskinit"})) {
            magiskKtag = true;
            
            std::string magiskPath = config.adbPath + "/magisk";
            std::string magiskDbPath = config.adbPath + "/magisk.db";
            
            if (fs::is_directory(magiskPath) && fs::is_regular_file(magiskDbPath)) {
                magiskTag = true;
            }
        }
    }

    // Check for APatch
    void detectAPatch() {
        if (fileContains(config.dmesgLog, "KP I commit_common_su")) {
            apatchKtag = true;
            
            std::string apPath = config.adbPath + "/ap";
            std::string apdPath = config.adbPath + "/apd";
            
            if (fs::is_directory(apPath) && fs::is_regular_file(apdPath)) {
                apatchTag = true;
            }
        }
    }

    // Determine root type
    void determineRootType() {
        int activeCount = kernelsuTag + suckysuTag + apatchTag + magiskTag;
        
        if (activeCount > 1) {
            // Multiple roots detected
            std::vector<std::string> detected;
            if (magiskTag) detected.push_back("Magisk");
            if (kernelsuTag) detected.push_back("KernelSU");
            if (apatchTag) detected.push_back("APatch");
            if (suckysuTag) detected.push_back("SuckySU");
            
            // Write to multiple type file
            std::ofstream multipleFile(config.multiplePath);
            for (size_t i = 0; i < detected.size(); i++) {
                multipleFile << detected[i];
                if (i < detected.size() - 1) {
                    multipleFile << ",";
                }
            }
            multipleFile.close();
            
            rootType = "Multiple";
        } else if (kernelsuTag) {
            rootType = "KernelSU";
        } else if (suckysuTag) {
            rootType = "SuckySU";
        } else if (apatchTag) {
            rootType = "APatch";
        } else if (magiskTag) {
            rootType = "Magisk";
        } else {
            rootType = "NULL";
        }
    }

    // Write root type to file
    void writeRootType() {
        std::ofstream typeFile(config.typePath);
        typeFile << rootType;
        typeFile.close();
    }

    // Check for multiple kernel types
    void detectMultipleKernelTypes() {
        int kernelCount = kernelsuKtag + apatchKtag + magiskKtag;
        
        if (kernelCount > 1 && rootType != "Multiple") {
            std::vector<std::string> kernelTypes;
            
            if (magiskKtag && rootType != "Magisk") {
                kernelTypes.push_back("Magisk");
            }
            if (kernelsuKtag && rootType != "KernelSU") {
                kernelTypes.push_back("KernelSU");
            }
            if (apatchKtag && rootType != "APatch") {
                kernelTypes.push_back("APatch");
            }
            
            if (!kernelTypes.empty()) {
                std::ofstream kernelTypeFile(config.kernelTypePath);
                for (size_t i = 0; i < kernelTypes.size(); i++) {
                    kernelTypeFile << kernelTypes[i];
                    if (i < kernelTypes.size() - 1) {
                        kernelTypeFile << ",";
                    }
                }
                kernelTypeFile.close();
            }
        }
    }

    // Get dmesg output
    void getDmesgLog() {
        std::string cmd = "dmesg > " + config.dmesgLog;
        system(cmd.c_str());
    }

    // Cleanup temporary files
    void cleanup() {
        if (fs::exists(config.dmesgLog)) {
            fs::remove(config.dmesgLog);
        }
    }

public:
    RootDetector(const RootDetectionConfig& cfg) : config(cfg) {
        // Set default paths
        if (config.dmesgLog.empty()) {
            config.dmesgLog = config.tseeConfig + "/dmesg.log";
        }
        if (config.typePath.empty()) {
            config.typePath = config.tseeConfig + "/type";
        }
        if (config.multiplePath.empty()) {
            config.multiplePath = config.tseeConfig + "/multipletype";
        }
        if (config.kernelTypePath.empty()) {
            config.kernelTypePath = config.tseeConfig + "/kerneltype";
        }
    }

    // Main detection function
    std::string detect() {
        getDmesgLog();
        
        detectKernelSU();
        detectMagisk();
        detectAPatch();
        
        determineRootType();
        writeRootType();
        
        detectMultipleKernelTypes();
        
        cleanup();
        
        return rootType;
    }

    std::string getRootType() const {
        return rootType;
    }

    bool isKernelSUDetected() const { return kernelsuKtag; }
    bool isApatchDetected() const { return apatchKtag; }
    bool isMagiskDetected() const { return magiskKtag; }
    bool isKernelSUActive() const { return kernelsuTag; }
    bool isSuckySUActive() const { return suckysuTag; }
    bool isApatchActive() const { return apatchTag; }
    bool isMagiskActive() const { return magiskTag; }
};

class SystemProperties {
private:
    PropertyManager propManager;
    std::string vbmetaSize;

    // Helper functions for property checking

    /**
     * Check if property matches expected value, otherwise reset it.
     * Also resets if value is empty.
     */
    void checkMissingMatchProp(const std::string& name, const std::string& expected) {
        std::string value = propManager.getprop(name);
        if (value.empty() || value != expected) {
            propManager.resetprop(name, expected);
        }
    }

    /**
     * If property contains substring, reset it to new value.
     */
    void containsResetProp(const std::string& name, const std::string& contains, const std::string& newval) {
        if (propManager.propertyContains(name, contains)) {
            propManager.resetprop(name, newval);
        }
    }

    /**
     * If property is empty, set it to expected value.
     */
    void checkMissingProp(const std::string& name, const std::string& expected) {
        if (propManager.propertyEmpty(name)) {
            propManager.resetprop(name, expected);
        }
    }

    /**
     * Check if property matches expected value, otherwise reset it.
     */
    void checkResetProp(const std::string& name, const std::string& expected) {
        std::string value = propManager.getprop(name);
        if (!value.empty() && value != expected) {
            propManager.resetprop(name, expected);
        }
    }

    /**
     * Initialize vbmeta size from device block or use default.
     */
    void initializeVbmetaSize() {
        std::string slotSuffix = propManager.getprop("ro.boot.slot_suffix");
        std::string device = "/dev/block/by-name/vbmeta" + slotSuffix;
        
        vbmetaSize = propManager.getBlockDeviceBlockSize(device);
        if (vbmetaSize.empty()) {
            vbmetaSize = "4096";
        }
    }

public:
    SystemProperties() : vbmetaSize("") {}

    /**
     * Apply all property state modifications to match expected security state.
     */
    void passpropState() {
        // Initialize vbmeta size
        initializeVbmetaSize();

        // Disable USB ADB debugging
        propManager.resetprop("sys.usb.adb.disabled", " ");

        // ===== Boot State Properties =====
        checkMissingMatchProp("ro.boot.vbmeta.device_state", "locked");
        checkMissingMatchProp("ro.boot.verifiedbootstate", "green");
        checkMissingMatchProp("ro.boot.veritymode", "enforcing");
        checkMissingMatchProp("ro.boot.warranty_bit", "0");
        checkMissingMatchProp("ro.boot.flash.locked", "1");

        // ===== Recovery Mode Check =====
        containsResetProp("vendor.boot.bootmode", "recovery", "unknown");
        containsResetProp("ro.boot.bootmode", "recovery", "unknown");
        containsResetProp("ro.bootmode", "recovery", "unknown");
        // ===== VBMeta Configuration =====
        checkMissingProp("ro.boot.vbmeta.invalidate_on_error", "yes");
        checkMissingProp("ro.boot.vbmeta.size", vbmetaSize);
        checkMissingProp("ro.boot.vbmeta.hash_alg", "sha256");
        checkMissingProp("ro.boot.vbmeta.avb_version", "1.2");

        // ===== Vendor Boot State =====
        checkResetProp("vendor.boot.vbmeta.device_state", "locked");
        checkResetProp("vendor.boot.verifiedbootstate", "green");
        checkResetProp("ro.secureboot.lockstate", "locked");

        // ===== Device-Specific Properties =====
        checkResetProp("ro.boot.realmebootstate", "green");
        checkResetProp("ro.vendor.boot.warranty_bit", "0");
        checkResetProp("sys.oem_unlock_allowed", "0");
        checkResetProp("ro.boot.realme.lockstate", "1");

        // ===== Build and Security Properties =====
        checkResetProp("ro.build.tags", "release-keys");
        checkResetProp("ro.crypto.state", "encrypted");
        checkResetProp("ro.vendor.warranty_bit", "0");
        checkResetProp("ro.force.debuggable", "0");
        checkResetProp("ro.build.type", "user");
        checkResetProp("ro.warranty_bit", "0");
        checkResetProp("ro.debuggable", "0");

        // ===== Emulation and Security Detection =====
        checkResetProp("ro.kernel.qemu", "");
        checkResetProp("ro.adb.secure", "1");
        checkResetProp("ro.secure", "1");
    }

    /**
     * Get property value directly (utility function).
     */
    std::string getProperty(const std::string& name) {
        return propManager.getprop(name);
    }

    /**
     * Set property value directly (utility function).
     */
    bool setProperty(const std::string& name, const std::string& value) {
        return propManager.resetprop(name, value);
    }

    /**
     * Get current vbmeta size.
     */
    std::string getVbmetaSize() const {
        return vbmetaSize;
    }
};

class RemoveConflicted{
public:
	void Apps(std::string[] applist){
		int length = sizeof(applist) / sizeof(applist[0]);
		for (int i = 0; i < length; ++i) {
			result = executeCommand("pm list" + applist[i]);
			if (!result == ""){
				executeCommand("pm uninstall" + applist[i]);
			}
		}
	}
};
