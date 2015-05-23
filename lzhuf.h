#pragma once
#include <cstdint>

size_t rwf_lzhuf_decompress(uint8_t* inBuf, size_t inSize, uint8_t* outBuf, uint16_t outSize, uint8_t initValue);
size_t lzhuf_compress(uint8_t* inBuf, size_t inSize, uint8_t* outBuf, size_t outSize, uint8_t initValue);
