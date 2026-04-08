/* Stub compiled when VL2_EMBED_XRAY is NOT defined (no xray binary found at
 * build time, or MSVC where .incbin is unsupported).
 * Satisfies the linker — all callers see g_xray_size == 0 and skip embedding.
 */
#include <cstddef>

extern "C" const unsigned char* g_xray_data = nullptr;
extern "C" const std::size_t    g_xray_size  = 0;
