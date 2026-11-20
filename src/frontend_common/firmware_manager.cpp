// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "firmware_manager.h"
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <random>
#include <common/fs/fs_paths.h>
#include <common/scope_exit.h>

#include "common/fs/fs.h"
#include "common/fs/path_util.h"

#include "common/logging.h"

#include "core/crypto/key_manager.h"
#include "frontend_common/content_manager.h"

#ifdef __ANDROID__
#include <jni.h>
#include <common/android/id_cache.h>
#include <common/android/android_common.h>
#endif

namespace {

std::filesystem::path StageKeyFiles(const std::filesystem::path& keys_dir,
                                    const std::vector<std::filesystem::path>& source_key_files) {
    const auto nonce = static_cast<unsigned long long>(
                           std::chrono::steady_clock::now().time_since_epoch().count()) ^
                       std::random_device{}();
    const auto staged = std::filesystem::temp_directory_path() /
                        ("lichii-key-install-" + std::to_string(nonce));
    std::error_code error;
    if (!std::filesystem::create_directories(staged, error) || error) {
        return {};
    }

    const auto replaced = [&source_key_files](const std::filesystem::path& path) {
        return std::any_of(source_key_files.begin(), source_key_files.end(),
                           [&path](const std::filesystem::path& source) {
                               return source.filename() == path.filename();
                           });
    };

    std::error_code exists_error;
    const bool keys_dir_exists = std::filesystem::exists(keys_dir, exists_error);
    if (exists_error) {
        return {};
    }
    if (keys_dir_exists) {
        std::error_code iteration_error;
        for (std::filesystem::directory_iterator it{keys_dir, iteration_error}, end;
             !iteration_error && it != end; it.increment(iteration_error)) {
            const auto& existing = it->path();
            if (replaced(existing)) {
                continue;
            }
            std::error_code copy_error;
            if (!std::filesystem::copy_file(existing, staged / existing.filename(),
                                            std::filesystem::copy_options::overwrite_existing,
                                            copy_error)) {
                return {};
            }
        }
        if (iteration_error) {
            return {};
        }
    }

    for (const auto& source : source_key_files) {
        std::error_code copy_error;
        if (!std::filesystem::copy_file(source, staged / source.filename(),
                                        std::filesystem::copy_options::overwrite_existing,
                                        copy_error)) {
            return {};
        }
    }
    return staged;
}

bool AreStagedKeysValid(const std::filesystem::path& staged) {
    auto manager = Core::Crypto::KeyManager::CreateForDirectory(staged);
    return manager && !manager->BaseDeriveNecessary();
}

}

FirmwareManager::KeyInstallResult
FirmwareManager::InstallKeys(std::string location, std::string extension) {
    LOG_INFO(Frontend, "Installing key files from {}", location);

    const auto keys_dir = Common::FS::GetEdenPath(Common::FS::EdenPath::KeysDir);

#ifdef __ANDROID__
    JNIEnv *env = Common::Android::GetEnvForThread();

    jstring jsrc = Common::Android::ToJString(env, location);

    jclass native = Common::Android::GetNativeLibraryClass();
    jmethodID getExtension = Common::Android::GetFileExtension();

    jstring jext = static_cast<jstring>(env->CallStaticObjectMethod(
        native,
        getExtension,
        jsrc
    ));

    std::string ext = Common::Android::GetJString(env, jext);

    if (ext != extension) {
        return ErrorWrongFilename;
    }

    jmethodID copyToStorage = Common::Android::GetCopyToStorage();
    jstring jdest = Common::Android::ToJString(env, keys_dir.string() + "/");

    jboolean copyResult = env->CallStaticBooleanMethod(
        native,
        copyToStorage,
        jsrc,
        jdest
    );

    if (!copyResult) {
        return ErrorFailedCopy;
    }
#else
    if (!location.ends_with(extension)) {
        return ErrorWrongFilename;
    }

    bool prod_keys_found = false;

    const std::filesystem::path prod_key_path = location;
    const std::filesystem::path key_source_path = prod_key_path.parent_path();

    if (!Common::FS::IsDir(key_source_path)) {
        return InvalidDir;
    }

    std::vector<std::filesystem::path> source_key_files;

    if (Common::FS::Exists(prod_key_path)) {
        prod_keys_found = true;
        source_key_files.emplace_back(prod_key_path);
    }

    if (Common::FS::Exists(key_source_path / "title.keys")) {
        source_key_files.emplace_back(key_source_path / "title.keys");
    }

    if (Common::FS::Exists(key_source_path / "key_retail.bin")) {
        source_key_files.emplace_back(key_source_path / "key_retail.bin");
    }

    if (source_key_files.empty() || !prod_keys_found) {
        return ErrorWrongFilename;
    }

    const auto staged = StageKeyFiles(keys_dir, source_key_files);
    if (staged.empty()) {
        return ErrorFailedCopy;
    }
    std::error_code cleanup_error;
    SCOPE_EXIT { std::filesystem::remove_all(staged, cleanup_error); };
    if (!AreStagedKeysValid(staged)) {
        return ErrorFailedInit;
    }

    std::error_code create_error;
    std::filesystem::create_directories(keys_dir, create_error);
    if (create_error) {
        return ErrorFailedCopy;
    }

    for (const auto& key_file : source_key_files) {
        const auto staged_key_file = staged / key_file.filename();
        const auto destination_key_file = keys_dir / key_file.filename();
        std::error_code error;
        if (!std::filesystem::copy_file(staged_key_file,
                                        destination_key_file,
                                        std::filesystem::copy_options::overwrite_existing,
                                        error)) {
            LOG_ERROR(Frontend,
                      "Failed to copy file {} to {}: {}",
                      staged_key_file.string(),
                      destination_key_file.string(),
                      error.message());
            return ErrorFailedCopy;
        }
    }
#endif

    // Reinitialize the key manager
    Core::Crypto::KeyManager::Instance().ReloadKeys();

    if (ContentManager::AreKeysPresent()) {
        return Success;
    }

    // Let the frontend handle everything else
    return ErrorFailedInit;
}

FirmwareManager::FirmwareCheckResult FirmwareManager::VerifyFirmware(Core::System &system) {
    if (!CheckFirmwarePresence(system)) {
        return ErrorFirmwareMissing;
    } else {
        const auto pair = GetFirmwareVersion(system);
        const auto result = pair.second;

        if (result.IsError()) {
            LOG_INFO(Frontend, "Unable to read firmware");
            return ErrorFirmwareCorrupted;
        }
    }

    return FirmwareGood;
}
