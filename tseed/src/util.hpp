#pragma once
#include <filesystem>
#include <string>
#include <cstdlib>
#include <iostream>

namespace fs = std::filesystem;

// 没什么必要的别名
//std::string TSEE="ts_enhancer_extreme";
//std::string TS="tricky_store";
// Zero Level
fs::path ADB = "/data/adb";
// One Level
fs::path ModulesDir = ADB / "modules";
fs::path Serviced = ADB / "service.d";
// Two Level
fs::path TSEE_Moddir = ModulesDir / "ts_enhancer_extreme";
fs::path TS_Moddir = ModulesDir / "tricky_store";
fs::path TSEE_Config = ADB / "ts_enhancer_extreme";
// Three Level
fs::path MultipleType = TSEE_Config / "multiple.txt";
fs::path KernelType = TSEE_Config / "kernel.txt";
fs::path TSEE_Log = TSEE_Config / "log" / "log.log";
fs::path TSEE_Binary = TSEE_Moddir/ "binaries";
fs::path RootTypeFile = TSEE_Config / "root.txt";
// END

class PropertyManager {
public:
    std::string getprop(const std::string& name) {
        std::string cmd = "getprop " + name;
        return executeCommand(cmd);
    }

    bool resetprop(const std::string& name, const std::string& value) {
        std::string cmd = "resetprop " + name + " \"" + value + "\"";
        return system(cmd.c_str()) == 0;
    }

    // Get block device block size
    std::string getBlockDeviceBlockSize(const std::string& device) {
        std::string cmd = "busybox blockdev --getbsz " + device;
        return executeCommand(cmd);
    }

    bool propertyContains(const std::string& name, const std::string& substring) {
        std::string value = getprop(name);
        return !value.empty() && value.find(substring) != std::string::npos;
    }

    bool propertyEquals(const std::string& name, const std::string& expected) {
        std::string value = getprop(name);
        return value == expected;
    }

    bool propertyEmpty(const std::string& name) {
        return getprop(name).empty();
    }
};

std::string executeCommand(const std::string& cmd) {
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "";
        
    std::string result;
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    pclose(pipe);
        
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
    }
    return result;
}