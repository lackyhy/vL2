#ifndef VL2_XRAY_EMBEDDED_H
#define VL2_XRAY_EMBEDDED_H

#include <cstddef>
#include <string>
/* When VL2_EMBED_XRAY is defined (set by CMake when a xray binary was found
 * and embedded at build time), g_xray_data / g_xray_size are valid.
 * Otherwise the stub provides null / 0 values and the launcher falls back to
 * searching the filesystem as usual.
 */
#ifdef VL2_EMBED_XRAY
extern "C" const unsigned char g_xray_data[];
extern "C" const std::size_t   g_xray_size;
inline bool xrayIsEmbedded() { return g_xray_size > 0; }
#else
inline const unsigned char* g_xray_data_ptr() { return nullptr; }
inline constexpr std::size_t g_xray_size = 0;
inline bool xrayIsEmbedded() { return false; }
#endif

/* Returns the path to the extracted xray binary, or "" if not embedded.
 * Declared here, defined in XrayLauncher.cpp.
 */
std::string extractEmbeddedXray();

#endif // VL2_XRAY_EMBEDDED_H
