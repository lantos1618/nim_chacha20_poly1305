# Constant-time Poly1305 implementation without external dependencies
# http://cr.yp.to/mac/poly1305-20050329.pdf
# https://datatracker.ietf.org/doc/html/rfc7539

import common
import poly1305_ct

# Re-export the constant-time implementation
export poly1305_ct.Poly1305, poly1305_ct.poly1305_init, poly1305_ct.poly1305_update, poly1305_ct.poly_pad

# Legacy compatibility wrappers if needed
proc poly1305_clamp*(poly: var Poly1305) =
    # Clamping is now handled internally in poly1305_ct
    discard