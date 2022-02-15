
# pure nim Chacha20, poly1305, chacha20_poly1305, xchacha20_poly1305

## ⚠️ This is WIP and needs review

### TODO
- [x] chacha20
	- [x] quarter round
	- [x] quarter rounds
	- [x] inner block
	- [x] add block
	- [x] serialize block
	- [x] chacha20_init
	- [x] chacha_xor
- [x] poly1305
	- [x] poly_pad
	- [x] poly_init
	- [x] poly_update
	- [ ] poly_finalize -  don't need at the moment
- [x] chacha20_poly1305
	- [x] chacha20_poly1305_encrypt
	- [x] chacha20_poly1305_decrypt
	- [ ] chacha20_poly1305_verify -  dont need atm
- [x] xchacha20_poly1305
	- [x] hchacha20_init
	- [x] hchacha20
	- [ ] streams
- [ ] factory that gives chacha(n) rounds
- [ ] add more test vectors
- [ ] make style more uniform
- [ ] add runable examples?


chacha20
- https://datatracker.ietf.org/doc/html/rfc7539
note xchacha, as of 2022 still in draft
- https://datatracker.ietf.org/doc/html/draft-arciszewski-xchacha-03
- https://www.ietf.org/archive/id/draft-irtf-cfrg-xchacha-03.txt
another chacha20 implementation:
- https://git.sr.ht/~ehmry/chacha20