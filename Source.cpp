#define _CRT_SECURE_NO_WARNINGS
#include <cstdio>
#include <cstdint>
#include <memory>
#include <intrin.h>
#include <unordered_map>
#include <string>
#include <direct.h>
#include <Windows.h>
#include <algorithm>
#include "lzhuf.h"
#include "mm3filelist.h"

void decryptHeader(uint8_t* buf, size_t size)
{
	uint8_t key = 0xAC;
	for (size_t i = 0; i < size; i++)
	{
		buf[i] = _rotl8(buf[i], 2) + key;
		key += 0x67;
	}
}

void encryptHeader(uint8_t* buf, size_t size)
{
	uint8_t key = 0xAC;
	for (size_t i = 0; i < size; i++)
	{
		buf[i] = _rotr8(buf[i] - key, 2);
		key += 0x67;
	}
}

uint16_t hashFileName(const char* fileName)
{
	uint16_t hash = 0;
	while (0 != *fileName)
	{
		uint8_t c = ((*fileName & 0x7F) < 0x60) ? *fileName : *fileName - 0x20;
		hash = _rotl16(hash, 9);	// xchg bl, bh | rol bx, 1
		hash += c;
		fileName++;
	}
	return hash;
}

#pragma pack(push, 1)
struct FileEntry
{
	uint16_t hash;
	uint16_t offsetLo;
	uint8_t offsetHi;
	uint16_t compressedSize;
	uint8_t padding;
	FileEntry(uint16_t hash, uint32_t offset, uint16_t compressedSize) : 
		hash(hash), offsetLo(offset & 0xFFFF), offsetHi((offset >> 16) & 0xFF), compressedSize(compressedSize), padding(0) {}
	uint32_t getOffset() const { return (offsetHi << 16) | offsetLo; }
	void setOffset(uint32_t off) { offsetHi = (off >> 16) & 0xFF; offsetLo = off & 0xFFFF; }
};
#pragma pack(pop)

std::unordered_map<uint16_t, std::string> hashToName;

void initFNames()
{
	for (int i = 0; i < _countof(filenames); i++)
	{
		hashToName[hashFileName(filenames[i])] = filenames[i];
	}
}

void saveFile(uint16_t hash, uint8_t* buf, size_t size, char* nameHint = nullptr)
{
	char fname[0x40];
	auto r = hashToName.find(hash);
	if (r != hashToName.end())
	{
		sprintf(fname, "out\\%s", r->second.c_str());
	}
	else if (nullptr != nameHint)
	{
		sprintf(fname, "out\\%s_%04X.BIN", nameHint, hash);
	}
	else
		sprintf(fname, "out\\_UNKNOWN_FILE_%04X.BIN", hash);
	printf("%s\n", fname);
	FILE* f = fopen(fname, "wb");
	if (nullptr == f)
	{
		printf("Can't create file: %s\n", fname);
		return;
	}
	fwrite(buf, 1, size, f);
	fclose(f);
}

uint8_t statFile(uint8_t* buf, size_t size)
{
	int stats[0x100] = { 0 };
	int max = 0;
	uint8_t maxC = 0;
	for (size_t i = 0; i < size; i++)
	{
		if ((buf[i] != 0) && (stats[buf[i]]++ > max))
		{
			max = stats[buf[i]];
			maxC = buf[i];
		}
	}
	return maxC;
}

uint8_t* readFile(const char* path, size_t& fSize)
{
	FILE* f = fopen(path, "rb");
	if (nullptr == f)
	{
		printf("Can't open: %s\n", path);
		return nullptr;
	}

	fseek(f, 0, SEEK_END);
	fSize = ftell(f);
	uint8_t* buf = (uint8_t*)malloc(fSize);
	if (nullptr == buf)
	{
		fclose(f);
		printf("File too big to fit in memory buffer ?\n");
		return nullptr;
	}
	fseek(f, 0, SEEK_SET);
	fread(buf, 1, fSize, f);
	fclose(f);
	return buf;
}

void dump(char* mm3ccPath)
{
	initFNames();

	size_t fSize;
	uint8_t* buf = readFile(mm3ccPath, fSize);
	if (nullptr == buf)
		return;

	size_t headerSize = (*(uint16_t*)buf) << 3;
	if (headerSize > fSize)
	{
		printf("Invalid header size.\n");
		free(buf);
		return;
	}
	decryptHeader(buf + 2, headerSize);

	_mkdir("out");

	FileEntry* entries = (FileEntry*)(buf + 2);
	// first two files are special, not compressed, those are two 0-ended strings
	for (size_t i = 0; i < headerSize / sizeof(FileEntry); i++)
	{
		size_t offset = entries[i].offsetHi << 16 | entries[i].offsetLo;
		uint16_t w1 = *(uint16_t*)(buf + offset);
		uint16_t w2 = _rotl16(*(uint16_t*)(buf + offset + 2), 8);
		printf(": %04X: %08X, %04X, %02X, %04X, %04X : ", entries[i].hash, offset, entries[i].compressedSize, entries[i].padding, w2, w1);
		if (offset + entries[i].compressedSize > fSize)
		{
			printf("invalid entry, skipping...\n");
			continue;
		}
		if (((w1 & 0xFF) == w1 >> 8) && (i >= 2))
		{
			// no need to check malloc result against nullptr, as it should be always possible to allocate 65k memory
			uint8_t* out = (uint8_t*)malloc(w2 + 0x100);
			/*size_t retSize = */rwf_lzhuf_decompress(buf + offset + 4, entries[i].compressedSize - 4, out, w2, (uint8_t)w1);
			saveFile(entries[i].hash, out, w2);
			free(out);
		}
		else
		{
			// not compressed, just dump
			char tmp[0x20];
			sprintf(tmp, "_NOT_COMPRESSED_%04X", i);
			saveFile(entries[i].hash, buf + offset, entries[i].compressedSize, tmp);
		}
	}
}

bool createFileList(char* path, std::vector<std::pair<std::string, size_t>>& fileList)
{
	WIN32_FIND_DATA wfd;
	std::string sp = path;
	sp += "\\*";
	HANDLE hFind = FindFirstFile(sp.c_str(), &wfd);
	if (INVALID_HANDLE_VALUE == hFind)
	{
		printf("Can't find any file: %s\n", path);
		return false;
	}

	do
	{
		if (!(wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
		{
			fileList.emplace_back(std::pair<std::string, size_t>(wfd.cFileName, wfd.nFileSizeLow));
		}
	}
	while (FindNextFile(hFind, &wfd) != 0);

	FindClose(hFind);
	return true;
}

void pack(char* path, char* outFileName)
{
	printf("Obtaining the list of files... ");
	std::vector<std::pair<std::string, size_t>> fileList;
	if (!createFileList(path, fileList))
		return;
	printf("[ %d files ]\n", fileList.size());

	std::vector<uint8_t> filesBuffer;
	std::vector<FileEntry> entries;
	auto it = std::remove_if(fileList.begin(), fileList.end(), [&entries, &filesBuffer, path](const std::pair<std::string, size_t>& arg)
	{
		bool ret = false;
		if (0 == arg.first.compare(0, strlen("_NOT_COMPRESSED_"), "_NOT_COMPRESSED_"))
		{
			std::string filePath = path;
			filePath += "\\" + arg.first;
			size_t fSize;
			printf("Adding %-40s", filePath.c_str());
			uint8_t* fbuf = readFile(filePath.c_str(), fSize);
			if (nullptr == fbuf)
				return false;

			size_t curOff = filesBuffer.size();
			filesBuffer.resize(curOff + fSize);
			memcpy(filesBuffer.data() + curOff, fbuf, fSize);
			free(fbuf);
			printf("[ s: %5d ->       ]\n", fSize);

			uint32_t hash;
			if (1 == sscanf(arg.first.c_str(), "_NOT_COMPRESSED_0000_%04X.BIN", &hash))
			{
				// put it as a first entry
				entries.emplace(entries.begin(), FileEntry((uint16_t)hash, curOff, (uint16_t)arg.second));
				ret = true;
			}
			else if (1 == sscanf(arg.first.c_str(), "_NOT_COMPRESSED_0001_%04X.BIN", &hash))
			{
				// put it as a second entry
				entries.emplace_back(FileEntry((uint16_t)hash, curOff, (uint16_t)arg.second));
				ret = true;
			}
		}
		return ret;
	});
	fileList.erase(it, fileList.end());

	for (auto& f : fileList)
	{
		std::string filePath = path;
		filePath += "\\" + f.first;
		size_t fSize;
		printf("Adding %-40s", filePath.c_str());
		uint8_t* fbuf = readFile(filePath.c_str(), fSize);
		if (nullptr == fbuf)
			return;
		printf("[ s: %5d -> ", fSize);
		if (fSize > 0xFFFF)
		{
			printf("file too big ]\n");
			free(fbuf);
			continue;
		}

		// +0x100 to not crash on really small files
		uint8_t* compressed = (uint8_t*)malloc(fSize + 0x100);
		if (nullptr == compressed)
		{
			printf("Can't allocate memory for compressed data.\n");
			free(fbuf);
			return;
		}
		uint8_t iv = statFile(fbuf, fSize);
		size_t compSize = lzhuf_compress(fbuf, fSize, compressed, fSize + 0x100, iv);
		free(fbuf);

		size_t curOff = filesBuffer.size();
		filesBuffer.resize(curOff + compSize + 4);
		filesBuffer[curOff] = iv;
		filesBuffer[curOff + 1] = iv;
		filesBuffer[curOff + 2] = (fSize >> 8) & 0xFF;
		filesBuffer[curOff + 3] = fSize & 0xFF;
		memcpy(filesBuffer.data() + curOff + 4, compressed, compSize);
		free(compressed);
		printf("%5d ]\n", compSize);

		uint32_t hash;
		if (1 == sscanf(f.first.c_str(), "_UNKNOWN_FILE_%04X.BIN", &hash))
		{
			entries.emplace_back(FileEntry((uint16_t)hash, curOff, (uint16_t)compSize + 4));
		}
		else
		{
			entries.emplace_back(FileEntry(hashFileName(f.first.c_str()), curOff, (uint16_t)compSize + 4));
		}
	}

	printf("Fixing offsets...\n");
	for (auto& e : entries)
		e.setOffset(e.getOffset() + sizeof(uint16_t) + sizeof(FileEntry)*entries.size());

	printf("Encrypting the header...\n");
	encryptHeader((uint8_t*)entries.data(), sizeof(FileEntry)*entries.size());

	printf("Writing %s...\n", outFileName);
	FILE* f = fopen(outFileName, "wb");
	if (nullptr == f)
	{
		printf("Can't create file: %s\n", outFileName);
		return;
	}
	uint16_t numOfEntries = (uint16_t)entries.size();
	fwrite(&numOfEntries, sizeof(uint16_t), 1, f);
	fwrite(entries.data(), sizeof(FileEntry), numOfEntries, f);
	fwrite(filesBuffer.data(), 1, filesBuffer.size(), f);
	fclose(f);
	printf("Done.\n");
}

int main(int argc, char *argv[])
{
	printf("\nMight and Magic III CC file packer/unpacker v1.0\n");
	printf("Copyrigh (c) 2015 ReWolf\n");
	printf("http://blog.rewolf.pl\n");
	printf("rewolf [at] rewolf.pl\n\n");
	if ((argc == 3) && (0 == strcmp(argv[1], "dump")))
	{
		dump(argv[2]);
	}
	else if ((argc == 4) && (0 == strcmp(argv[1], "pack")))
	{
		pack(argv[2], argv[3]);
	}
	else
	{
		printf("Usage:\n\n");
		printf("Unpack:\t%s dump input_file.cc\n", argv[0]);
		printf("Pack:\t%s pack input_directory output_file.cc\n", argv[0]);
	}
	return 0;
}
