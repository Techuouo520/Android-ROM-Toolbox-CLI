/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <sysexits.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <iostream>
#include <limits>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <android-base/file.h>
#include <android-base/parseint.h>
#include <liblp/liblp.h>
#include "artb_cpu.h"
#include "artb_sparse_reader.h"

using namespace android::fs_mgr;
using android::base::unique_fd;
using android::base::borrowed_fd;
using ArtbSparsePtr = std::unique_ptr<artb_sparse_reader, decltype(&artb_sparse_reader_close)>;

static std::unique_ptr<LpMetadata> ReadSparseMetadata(const artb_sparse_reader* reader, int fd, uint32_t slot) {
    std::vector<uint8_t> headers(GetBackupGeometryOffset() + LP_METADATA_GEOMETRY_SIZE);
    if (!artb_sparse_reader_read(reader, fd, headers.data(), headers.size(), 0)) return nullptr;
    LpMetadataGeometry geometry;
    if (!ParseGeometryFromSuperPartition(headers.data(), headers.size(), &geometry) || slot >= geometry.metadata_slot_count || geometry.metadata_max_size == 0) return nullptr;
    uint64_t metadata_region = uint64_t(geometry.metadata_max_size) * geometry.metadata_slot_count;
    if (metadata_region > (UINT64_MAX - headers.size()) / 2) return nullptr;
    uint64_t region = headers.size() + metadata_region * 2;
    if (region > artb_sparse_reader_size(reader)) return nullptr;
    std::vector<uint8_t> blob(LP_METADATA_GEOMETRY_SIZE + geometry.metadata_max_size);
    uint64_t geometry_offset = memcmp(headers.data() + GetPrimaryGeometryOffset(), &geometry, sizeof(geometry)) == 0 ? GetPrimaryGeometryOffset() : GetBackupGeometryOffset();
    memcpy(blob.data(), headers.data() + geometry_offset, LP_METADATA_GEOMETRY_SIZE);
    for (int backup = 0; backup < 2; ++backup) {
        uint64_t offset = headers.size() + uint64_t(geometry.metadata_max_size) * (slot + (backup ? uint64_t(geometry.metadata_slot_count) : 0));
        if (!artb_sparse_reader_read(reader, fd, blob.data() + LP_METADATA_GEOMETRY_SIZE, geometry.metadata_max_size, offset)) return nullptr;
        auto metadata = ReadFromImageBlob(blob.data(), blob.size());
        if (metadata) return metadata;
    }
    return nullptr;
}

class ImageExtractor final {
  public:
    ImageExtractor(std::vector<unique_fd>&& image_fds, std::vector<ArtbSparsePtr>&& sparse_readers, std::vector<std::string>&& image_paths, std::unique_ptr<LpMetadata>&& metadata,
                   std::unordered_set<std::string>&& partitions, const std::string& output_dir,
                   uint32_t jobs, bool progress);

    bool Extract();

  private:
    bool BuildPartitionList();
    bool ExtractPartition(const LpMetadataPartition* partition);
    bool ExtractExtent(const LpMetadataExtent& extent, int output_fd);
    void ReportProgress(uint64_t total_bytes, size_t total_parts);

    std::vector<unique_fd> image_fds_;
    std::vector<ArtbSparsePtr> sparse_readers_;
    std::vector<std::string> image_paths_;
    std::unique_ptr<LpMetadata> metadata_;
    std::unordered_set<std::string> partitions_;
    std::string output_dir_;
    uint32_t jobs_;
    bool progress_;
    std::atomic_uint64_t done_bytes_ = 0;
    std::atomic_size_t done_parts_ = 0;
    std::unordered_map<std::string, const LpMetadataPartition*> partition_map_;
};

// Note that "sparse" here refers to filesystem sparse, not the Android sparse
// file format.
class SparseWriter final {
  public:
    SparseWriter(borrowed_fd output_fd, uint32_t block_size, std::atomic_uint64_t* done_bytes);

    bool WriteExtent(borrowed_fd image_fd, const artb_sparse_reader* reader, const std::string& path, const LpMetadataExtent& extent);
    bool Finish();

  private:
    bool WriteBlocks(const uint8_t* data, size_t length);
    bool WriteData(const uint8_t* data, size_t length);

    borrowed_fd output_fd_;
    uint32_t block_size_;
    std::atomic_uint64_t* done_bytes_;
    off_t hole_size_ = 0;
};

/* Prints program usage to |where|. */
static std::string JsonString(const std::string& value) {
    std::string out = "\"";
    for (char c : value) {
        if (c == '"' || c == '\\') out += '\\';
        if (static_cast<unsigned char>(c) < 0x20) {
            char escaped[8];
            snprintf(escaped, sizeof(escaped), "\\u%04x", c);
            out += escaped;
        } else {
            out += c;
        }
    }
    return out + "\"";
}

// Records everything lpmake needs to rebuild the same layout: geometry, devices, groups and partitions.
static bool WriteArtbMetadata(const LpMetadata& metadata, const std::string& path) {
    FILE* file = fopen(path.c_str(), "wb");
    if (!file) return false;
    std::string out = "{\n";
    out += "  \"major_version\": " + std::to_string(metadata.header.major_version) + ",\n";
    out += "  \"minor_version\": " + std::to_string(metadata.header.minor_version) + ",\n";
    out += "  \"header_flags\": " + std::to_string(metadata.header.flags) + ",\n";
    out += "  \"metadata_max_size\": " + std::to_string(metadata.geometry.metadata_max_size) + ",\n";
    out += "  \"metadata_slot_count\": " + std::to_string(metadata.geometry.metadata_slot_count) + ",\n";
    out += "  \"logical_block_size\": " + std::to_string(metadata.geometry.logical_block_size) + ",\n";
    out += "  \"block_devices\": [";
    for (size_t i = 0; i < metadata.block_devices.size(); i++) {
        const auto& device = metadata.block_devices[i];
        out += std::string(i ? ",\n" : "\n") + "    {\"name\": " + JsonString(GetBlockDevicePartitionName(device)) + ", \"size\": " + std::to_string(device.size) + ", \"first_logical_sector\": " + std::to_string(device.first_logical_sector) + ", \"alignment\": " + std::to_string(device.alignment) + ", \"alignment_offset\": " + std::to_string(device.alignment_offset) + ", \"flags\": " + std::to_string(device.flags) + "}";
    }
    out += "\n  ],\n  \"groups\": [";
    for (size_t i = 0; i < metadata.groups.size(); i++) {
        const auto& group = metadata.groups[i];
        out += std::string(i ? ",\n" : "\n") + "    {\"name\": " + JsonString(GetPartitionGroupName(group)) + ", \"maximum_size\": " + std::to_string(group.maximum_size) + ", \"flags\": " + std::to_string(group.flags) + "}";
    }
    out += "\n  ],\n  \"partitions\": [";
    for (size_t i = 0; i < metadata.partitions.size(); i++) {
        const auto& partition = metadata.partitions[i];
        uint64_t size = 0;
        std::string extents;
        for (uint32_t e = 0; e < partition.num_extents; e++) {
            const auto& extent = metadata.extents[partition.first_extent_index + e];
            size += extent.num_sectors * LP_SECTOR_SIZE;
            extents += std::string(e ? ", " : "") + "{\"num_sectors\": " + std::to_string(extent.num_sectors) + ", \"target_type\": " + std::to_string(extent.target_type) + ", \"target_data\": " + std::to_string(extent.target_data) + ", \"target_source\": " + std::to_string(extent.target_source) + "}";
        }
        std::string group = partition.group_index < metadata.groups.size() ? GetPartitionGroupName(metadata.groups[partition.group_index]) : "";
        out += std::string(i ? ",\n" : "\n") + "    {\"name\": " + JsonString(GetPartitionName(partition)) + ", \"group\": " + JsonString(group) + ", \"attributes\": " + std::to_string(partition.attributes) + ", \"size\": " + std::to_string(size) + ", \"extents\": [" + extents + "]}";
    }
    out += "\n  ]\n}\n";
    bool ok = fwrite(out.data(), 1, out.size(), file) == out.size();
    return fclose(file) == 0 && ok;
}

static int usage(int /* argc */, char* argv[]) {
    fprintf(stderr,
            "%s - command-line tool for extracting partition images from super\n"
            "\n"
            "Usage:\n"
            "  %s [options...] SUPER_IMAGE [OUTPUT_DIR]\n"
            "\n"
            "The SUPER_IMAGE argument is mandatory and expected to contain\n"
            "the metadata. Additional super images are referenced with '-i' as needed to extract\n"
            "the desired partition[s].\n"
            "Default OUTPUT_DIR is '.'.\n"
            "\n"
            "Options:\n"
            "  -i, --image=IMAGE        Use the given file as an additional super image.\n"
            "                           This can be specified multiple times.\n"
            "  -p, --partition=NAME     Extract the named partition. This can\n"
            "                           be specified multiple times.\n"
            "  -j, --jobs=COUNT         Extract partitions concurrently.\n"
            "      --artb-progress      Print machine-readable progress lines.\n"
            "      --artb-metadata=FILE Write the slot's LP metadata as JSON for rebuilding.\n"
            "  -S, --slot=NUM           Slot number (default is 0).\n",
            argv[0], argv[0]);
    return EX_USAGE;
}

int main(int argc, char* argv[]) {
    // clang-format off
    struct option options[] = {
        { "image",      required_argument,  nullptr, 'i' },
        { "jobs",       required_argument,  nullptr, 'j' },
        { "partition",  required_argument,  nullptr, 'p' },
        { "slot",       required_argument,  nullptr, 'S' },
        { "artb-progress", no_argument,     nullptr, 'B' },
        { "artb-metadata", required_argument, nullptr, 'M' },
        { nullptr,      0,                  nullptr, 0 },
    };
    // clang-format on

    uint32_t slot_num = 0;
    uint32_t jobs = artb_logical_cpus();
    bool progress = false;
    std::string metadata_json;
    std::unordered_set<std::string> partitions;
    std::vector<std::string> image_files;

    int rv, index;
    while ((rv = getopt_long_only(argc, argv, "+i:j:p:S:h", options, &index)) != -1) {
        switch (rv) {
            case 'h':
                usage(argc, argv);
                return EX_OK;
            case '?':
                std::cerr << "Unrecognized argument.\n";
                return usage(argc, argv);
            case 'S':
                if (!android::base::ParseUint(optarg, &slot_num)) {
                    std::cerr << "Slot must be a valid unsigned number.\n";
                    return usage(argc, argv);
                }
                break;
            case 'i':
                image_files.push_back(optarg);
                break;
            case 'j':
                if (!android::base::ParseUint(optarg, &jobs) || jobs == 0) {
                    std::cerr << "Jobs must be a positive unsigned number.\n";
                    return usage(argc, argv);
                }
                break;
            case 'p':
                partitions.emplace(optarg);
                break;
            case 'B':
                progress = true;
                break;
            case 'M':
                metadata_json = optarg;
                break;
        }
    }

    if (optind + 1 > argc) {
        std::cerr << "Missing super image argument.\n";
        return usage(argc, argv);
    }
    image_files.emplace(image_files.begin(), argv[optind++]);

    std::string output_dir = ".";
    if (optind + 1 <= argc) {
        output_dir = argv[optind++];
    }

    std::unique_ptr<LpMetadata> metadata;
    std::vector<unique_fd> fds;
    std::vector<ArtbSparsePtr> sparse_readers;
    std::vector<std::string> image_paths;

    for (std::size_t index = 0; index < image_files.size(); ++index) {
        std::string super_path = image_files[index];

        // Done reading arguments; open super.img. PartitionOpener will decorate
        // relative paths with /dev/block/by-name, so get an absolute path here.
        std::string abs_super_path;
        if (!android::base::Realpath(super_path, &abs_super_path)) {
            std::cerr << "realpath failed: " << super_path << ": " << strerror(errno) << "\n";
            return EX_OSERR;
        }

        unique_fd fd(open(super_path.c_str(), O_RDONLY | O_CLOEXEC | O_BINARY));
        if (fd < 0) {
            std::cerr << "open failed: " << abs_super_path << ": " << strerror(errno) << "\n";
            return EX_OSERR;
        }

        uint32_t magic = 0;
        if (!android::base::ReadFullyAtOffset(fd, &magic, sizeof(magic), 0)) return EX_IOERR;
        ArtbSparsePtr reader(nullptr, artb_sparse_reader_close);
        if (magic == 0xed26ff3a) {
            reader.reset(artb_sparse_reader_open(super_path.c_str()));
            if (!reader) { std::cerr << "Invalid sparse image '" << super_path << "': " << strerror(errno) << "\n"; return EX_DATAERR; }
        }

        if (!metadata) {
            metadata = reader ? ReadSparseMetadata(reader.get(), fd.get(), slot_num) : ReadMetadata(abs_super_path, slot_num);
            if (!metadata) {
                std::cerr << "Could not read metadata from the super image file '"
                          << super_path
                          << "'.\n";
                return EX_USAGE;
            }
        }

        fds.emplace_back(std::move(fd));
        sparse_readers.emplace_back(std::move(reader));
        image_paths.emplace_back(std::move(super_path));
    }

    if (!metadata_json.empty() && !WriteArtbMetadata(*metadata, metadata_json)) {
        std::cerr << "Could not write metadata to '" << metadata_json << "'.\n";
        return EX_CANTCREAT;
    }

    // Now do actual extraction.
    ImageExtractor extractor(std::move(fds), std::move(sparse_readers), std::move(image_paths), std::move(metadata), std::move(partitions), output_dir, jobs, progress);
    if (!extractor.Extract()) {
        return EX_SOFTWARE;
    }
    return EX_OK;
}

ImageExtractor::ImageExtractor(std::vector<unique_fd>&& image_fds, std::vector<ArtbSparsePtr>&& sparse_readers, std::vector<std::string>&& image_paths, std::unique_ptr<LpMetadata>&& metadata,
                               std::unordered_set<std::string>&& partitions,
                               const std::string& output_dir, uint32_t jobs, bool progress)
    : image_fds_(std::move(image_fds)),
      sparse_readers_(std::move(sparse_readers)),
      image_paths_(std::move(image_paths)),
      metadata_(std::move(metadata)),
      partitions_(std::move(partitions)),
      output_dir_(output_dir),
      jobs_(jobs),
      progress_(progress) {}

void ImageExtractor::ReportProgress(uint64_t total_bytes, size_t total_parts) {
    printf("progress %llu %llu %llu %llu\n", static_cast<unsigned long long>(done_bytes_.load(std::memory_order_relaxed)), static_cast<unsigned long long>(total_bytes), static_cast<unsigned long long>(done_parts_.load(std::memory_order_relaxed)), static_cast<unsigned long long>(total_parts));
    fflush(stdout);
}

bool ImageExtractor::Extract() {
    std::filesystem::create_directories(output_dir_);
    if (!BuildPartitionList()) {
        return false;
    }

    std::vector<std::pair<std::string, const LpMetadataPartition*>> work(partition_map_.begin(),
                                                                        partition_map_.end());
    uint64_t total_bytes = 0;
    for (const auto& [name, info] : work) {
        for (uint32_t i = 0; i < info->num_extents; i++) total_bytes += metadata_->extents[info->first_extent_index + i].num_sectors * LP_SECTOR_SIZE;
    }
    std::mutex report_mutex;
    std::condition_variable report_cv;
    bool finished = false;
    std::thread reporter;
    if (progress_) {
        ReportProgress(total_bytes, work.size());
        reporter = std::thread([&]() {
            std::unique_lock lock(report_mutex);
            while (!report_cv.wait_for(lock, std::chrono::milliseconds(100), [&] { return finished; })) ReportProgress(total_bytes, work.size());
        });
    }
    std::atomic_size_t next = 0;
    std::atomic_bool success = true;
    auto worker = [&]() {
        while (success.load(std::memory_order_relaxed)) {
            size_t index = next.fetch_add(1, std::memory_order_relaxed);
            if (index >= work.size()) return;
            const auto& [name, info] = work[index];
            if (!progress_) std::cout << "Attempting to extract partition '" << name << "'...\n";
            if (!ExtractPartition(info)) {
                success.store(false, std::memory_order_relaxed);
            } else {
                done_parts_.fetch_add(1, std::memory_order_relaxed);
            }
        }
    };
    size_t worker_count = std::min<size_t>(jobs_, work.size());
    std::vector<std::thread> workers;
    workers.reserve(worker_count);
    for (size_t index = 0; index < worker_count; ++index) workers.emplace_back(worker);
    for (auto& thread : workers) thread.join();
    if (progress_) {
        {
            std::lock_guard lock(report_mutex);
            finished = true;
        }
        report_cv.notify_all();
        reporter.join();
        ReportProgress(total_bytes, work.size());
    }
    return success.load(std::memory_order_relaxed);
}

bool ImageExtractor::BuildPartitionList() {
    bool extract_all = partitions_.empty();

    for (const auto& partition : metadata_->partitions) {
        auto name = GetPartitionName(partition);
        if (extract_all || partitions_.count(name)) {
            partition_map_[name] = &partition;
            partitions_.erase(name);
        }
    }

    if (!extract_all && !partitions_.empty()) {
        std::cerr << "Could not find partition: " << *partitions_.begin() << "\n";
        return false;
    }
    return true;
}

bool ImageExtractor::ExtractPartition(const LpMetadataPartition* partition) {
    // Validate the extents and find the total image size.
    uint64_t total_size = 0;
    for (uint32_t i = 0; i < partition->num_extents; i++) {
        uint32_t index = partition->first_extent_index + i;
        const LpMetadataExtent& extent = metadata_->extents[index];
        if (!progress_) std::cout << "  Dealing with extent " << i << " from target source " << extent.target_source << "...\n";

        if (extent.target_type != LP_TARGET_TYPE_LINEAR) {
            std::cerr << "Unsupported target type in extent: " << extent.target_type << "\n";
            return false;
        }
        if (extent.target_source >= image_fds_.size()) {
            std::cerr << "Insufficient number of super images passed, need at least " << extent.target_source + 1 << ".\n";
            return false;
        }
        total_size += extent.num_sectors * LP_SECTOR_SIZE;
    }

    // Make a temporary file so we can import it with sparse_file_read.
    std::string output_path = output_dir_ + "/" + GetPartitionName(*partition) + ".img";
    unique_fd output_fd(open(output_path.c_str(), O_RDWR | O_CLOEXEC | O_CREAT | O_TRUNC | O_BINARY, 0644));
    if (output_fd < 0) {
        std::cerr << "open failed: " << output_path << ": " << strerror(errno) << "\n";
        return false;
    }

    SparseWriter writer(output_fd, metadata_->geometry.logical_block_size, progress_ ? &done_bytes_ : nullptr);

    // Extract each extent into output_fd.
    for (uint32_t i = 0; i < partition->num_extents; i++) {
        uint32_t index = partition->first_extent_index + i;
        const LpMetadataExtent& extent = metadata_->extents[index];

        if (!writer.WriteExtent(image_fds_[extent.target_source], sparse_readers_[extent.target_source].get(), image_paths_[extent.target_source], extent)) {
            return false;
        }
    }
    return writer.Finish();
}

SparseWriter::SparseWriter(borrowed_fd output_fd, uint32_t block_size, std::atomic_uint64_t* done_bytes)
    : output_fd_(output_fd), block_size_(block_size), done_bytes_(done_bytes) {}

bool SparseWriter::WriteExtent(borrowed_fd image_fd, const artb_sparse_reader* reader, const std::string& path, const LpMetadataExtent& extent) {
    uint64_t remaining_bytes = extent.num_sectors * LP_SECTOR_SIZE;
    if (block_size_ == 0 || remaining_bytes % block_size_ != 0) { std::cerr << "extent is not block-aligned\n"; return false; }
    size_t read_size = std::max<size_t>(block_size_, (size_t(1024 * 1024) / block_size_) * block_size_);
    auto buffer = std::make_unique<uint8_t[]>(read_size);
    unique_fd private_fd;
    if (reader) { private_fd.reset(open(path.c_str(), O_RDONLY | O_CLOEXEC | O_BINARY)); if (private_fd < 0) { std::cerr << "open failed: " << path << ": " << strerror(errno) << "\n"; return false; } }

    off64_t super_offset = extent.target_data * LP_SECTOR_SIZE;

    while (remaining_bytes) {
        size_t bytes = static_cast<size_t>(std::min<uint64_t>(remaining_bytes, read_size));
        if (!(reader ? artb_sparse_reader_read(reader, private_fd.get(), buffer.get(), bytes, super_offset) : android::base::ReadFullyAtOffset(image_fd, buffer.get(), bytes, super_offset))) {
            std::cerr << "read failed: " << strerror(errno) << "\n";
            return false;
        }
        if (!WriteBlocks(buffer.get(), bytes)) {
            return false;
        }
        remaining_bytes -= bytes;
        super_offset += bytes;
        if (done_bytes_) done_bytes_->fetch_add(bytes, std::memory_order_relaxed);
    }
    return true;
}

static bool ShouldSkipChunk(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (data[i] != 0) {
            return false;
        }
    }
    return true;
}

bool SparseWriter::WriteBlocks(const uint8_t* data, size_t length) {
    size_t run_start = 0;
    for (size_t offset = 0; offset < length; offset += block_size_) {
        if (!ShouldSkipChunk(data + offset, block_size_)) continue;
        if (offset > run_start && !WriteData(data + run_start, offset - run_start)) return false;
        hole_size_ += block_size_;
        run_start = offset + block_size_;
    }
    return run_start == length || WriteData(data + run_start, length - run_start);
}

bool SparseWriter::WriteData(const uint8_t* data, size_t length) {
    if (hole_size_) {
        if (lseek(output_fd_.get(), hole_size_, SEEK_CUR) < 0) {
            std::cerr << "lseek failed: " << strerror(errno) << "\n";
            return false;
        }
        hole_size_ = 0;
    }
    if (!android::base::WriteFully(output_fd_, data, length)) {
        std::cerr << "write failed: " << strerror(errno) << "\n";
        return false;
    }
    return true;
}

bool SparseWriter::Finish() {
    if (hole_size_) {
        off_t offset = lseek(output_fd_.get(), 0, SEEK_CUR);
        if (offset < 0) {
            std::cerr << "lseek failed: " << strerror(errno) << "\n";
            return false;
        }
        if (ftruncate(output_fd_.get(), offset + hole_size_) < 0) {
            std::cerr << "ftruncate failed: " << strerror(errno) << "\n";
            return false;
        }
    }
    return true;
}
