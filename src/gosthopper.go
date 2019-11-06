//
//                                                       /\_/\
//                                                      ( 0.0 )
//                                                       = ^ =
//                                                       /|_|\
//                                                      (") (")=~
//
//
// ~=  GOSThopper  =~
//
// Implementation of block cipher Kuznyechik, GOST R 34.12-2015
//
// Author: Alexander Venedioukhin, dxdt.ru
// Date: 17/02/2019
// Free software, distribution unlimited.
//
// Supplementary files:
//		docipher.go
//		docipher_amd64.go
//		docipher_amd64.s
//
// Kuznyechik is 128-bit block cipher with keys of 256 bits, 
// standardized in 2015 as GOST R 34.12-2015 (Russian Federation 
// National Standard).
//
// This is example implementation in Go using assembly for x64/amd64 
// platform. It runs very fast on this platform. 
// 
// For other platforms - there is universal implementation in more 
// or less pure Go included. It means, that on platforms 
// different from x64/amd64 compiled code will be orders of magnitude 
// slower (100 times or so).
//
// See gosthopper_amd64.s for assembly.
//
// This version implements standard interface for crypto/cipher package.
// Particularly - with GCM module.
//
// General usage:
// c, err := NewCipher(key) - creates and initializes new instance with 
// key given. Returns cipher.Block with Kuznyechik;
// c.Encrypt(dst,src), c.Decrypt(dst,src) - block encryption
// and decryption methods;
//
// gosthopper.DoEncrypt(block, round_keys) - cipher encrypt procedure,
// low level;
// gosthopper.DoDecrypt(block, round_keys) - cipher decrypt procedure,
// low level.
//
// There are simple counter mode functions:
//
// gosthopper.CM_Encrypt(nonce_iv, key, plain_text);
// gosthopper.CM_Decrypt(nonce_iv, key, cipher_text);
//
// nonce_iv is a counter initial state, it will be incremented for 
// each block. The same value must be set for successful decryption.
// In counter mode nonce_iv must be never reused with the same key for
// encryption.
//
// To use in GCM mode of operation:
// ---
// import "crypto/cipher"
//
// kCipher, err := NewCipher(key)
// kuznecGCM, err := cipher.NewGCM(kCipher)
// [...]
// kuznecGCM.Seal(...), kuznecGCM.Open(...)
// ---
//
// Other functions:
// gosthopper.InitCipher() - initializes (computes values) in-memory 
// lookup tables 
// needed for encryption/decryption;
//
// More usage examples:
// ---
// gosthopper.InitCipher()
// RoundKeys = gosthopper.StretchKey(MainKey)
// CipherText = gosthopper.DoEncrypt(PlainText, RoundKeys)
// DecRoundKeys = gosthopper.GetDecryptRoundKeys(RoundKeys)
// PlainText = gosthopper.DoDecrypt(CipherText, DecryptRoundKeys))
// ---
//
// Kuznyechik or Kuznechik (Grasshopper in Russian) cipher is based on
// substitution-permutation network and use Feistel cipher to derive 
// round keys.
// This implementation uses a precomputed lookup tables 
// of transformations and cipher assembly implementation (amd64)
// to speed up encryption and decryption process.
//
//
// Reference:
// C implementation - https://github.com/mjosaarinen/kuznechik/
// SAGE implementation - https://github.com/okazymyrov/kuznechik/
// Cipher informational RFC 7801 - https://tools.ietf.org/html/rfc7801

package gosthopper

import (
	"crypto/cipher"
)

type GOSThopper struct {
	enc_keys [10][16]uint8
	dec_keys [10][16]uint8
}

// Flag to indicate that cipher lookup tables are ready.
var CipherInitialized = false;

// 128-bit block cipher.
// Defined as a constant here, but most of code below use 
// hardcoded plain 16.
const BlockSize = 16

// Pi(S) substitution lookup table.
var Pi_table = [256]uint8 {

	0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16,
	0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
	0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA,
	0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
	0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21,
	0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
	0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0,
	0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
	0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB,
	0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
	0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12,
	0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
	0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7,
	0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
	0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E,
	0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
	0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9,
	0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
	0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC,
	0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
	0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44,
	0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
	0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F,
	0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
	0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7,
	0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
	0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE,
	0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
	0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B,
	0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
	0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0,
	0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6,

}

// Inverse Pi(S) substitution lookup table.
var Pi_inverse_table = [256]uint8 {

	0xA5, 0x2D, 0x32, 0x8F, 0x0E, 0x30, 0x38, 0xC0,
	0x54, 0xE6, 0x9E, 0x39, 0x55, 0x7E, 0x52, 0x91,
	0x64, 0x03, 0x57, 0x5A, 0x1C, 0x60, 0x07, 0x18,
	0x21, 0x72, 0xA8, 0xD1, 0x29, 0xC6, 0xA4, 0x3F,
	0xE0, 0x27, 0x8D, 0x0C, 0x82, 0xEA, 0xAE, 0xB4,
	0x9A, 0x63, 0x49, 0xE5, 0x42, 0xE4, 0x15, 0xB7,
	0xC8, 0x06, 0x70, 0x9D, 0x41, 0x75, 0x19, 0xC9,
	0xAA, 0xFC, 0x4D, 0xBF, 0x2A, 0x73, 0x84, 0xD5,
	0xC3, 0xAF, 0x2B, 0x86, 0xA7, 0xB1, 0xB2, 0x5B,
	0x46, 0xD3, 0x9F, 0xFD, 0xD4, 0x0F, 0x9C, 0x2F,
	0x9B, 0x43, 0xEF, 0xD9, 0x79, 0xB6, 0x53, 0x7F,
	0xC1, 0xF0, 0x23, 0xE7, 0x25, 0x5E, 0xB5, 0x1E,
	0xA2, 0xDF, 0xA6, 0xFE, 0xAC, 0x22, 0xF9, 0xE2,
	0x4A, 0xBC, 0x35, 0xCA, 0xEE, 0x78, 0x05, 0x6B,
	0x51, 0xE1, 0x59, 0xA3, 0xF2, 0x71, 0x56, 0x11,
	0x6A, 0x89, 0x94, 0x65, 0x8C, 0xBB, 0x77, 0x3C,
	0x7B, 0x28, 0xAB, 0xD2, 0x31, 0xDE, 0xC4, 0x5F,
	0xCC, 0xCF, 0x76, 0x2C, 0xB8, 0xD8, 0x2E, 0x36,
	0xDB, 0x69, 0xB3, 0x14, 0x95, 0xBE, 0x62, 0xA1,
	0x3B, 0x16, 0x66, 0xE9, 0x5C, 0x6C, 0x6D, 0xAD,
	0x37, 0x61, 0x4B, 0xB9, 0xE3, 0xBA, 0xF1, 0xA0,
	0x85, 0x83, 0xDA, 0x47, 0xC5, 0xB0, 0x33, 0xFA,
	0x96, 0x6F, 0x6E, 0xC2, 0xF6, 0x50, 0xFF, 0x5D,
	0xA9, 0x8E, 0x17, 0x1B, 0x97, 0x7D, 0xEC, 0x58,
	0xF7, 0x1F, 0xFB, 0x7C, 0x09, 0x0D, 0x7A, 0x67,
	0x45, 0x87, 0xDC, 0xE8, 0x4F, 0x1D, 0x4E, 0x04,
	0xEB, 0xF8, 0xF3, 0x3E, 0x3D, 0xBD, 0x8A, 0x88,
	0xDD, 0xCD, 0x0B, 0x13, 0x98, 0x02, 0x93, 0x80,
	0x90, 0xD0, 0x24, 0x34, 0xCB, 0xED, 0xF4, 0xCE,
	0x99, 0x10, 0x44, 0x40, 0x92, 0x3A, 0x01, 0x26,
	0x12, 0x1A, 0x48, 0x68, 0xF5, 0x81, 0x8B, 0xC7,
	0xD6, 0x20, 0x0A, 0x08, 0x00, 0x4C, 0xD7, 0x74,

}
// L-function (transformation) vector.
var L_vector = [16]uint8 {	0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB,
							0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01, }

// Lookup table for precomputed encryption transformations (LS).
var LS_enc_lookup [16][256][16]uint8

// Lookup table for precomputed inverse of L-function.
var L_inv_lookup [16][256][16]uint8

// Lookup table for precomputed decryption transformations (SL).
var SL_dec_lookup [16][256][16]uint8

func GF2_mul(x,y uint8) uint8 {
// Multiplication in GF(2^8) with P(x)=x^8+x^7+x^6+x+1.
// Used by L-function.
var z uint8
	z = 0
	for y != 0 { 
		if y & 1 == 1 {
			z = z ^ x
		} 
		if x & 0x80 != 0 {
				x = (x << 1) ^ 0xC3
		} else {
				x = x << 1
		}
		y = y >> 1
	}
	return z
}

func L(block [16]uint8) [16]uint8 {
// Takes 128-bit block and returns result of L-function.
var i,j int
var x uint8

	for j = 0; j < 16; j++ { // 16 rounds of transformation R (LFSR).
	// Single round of R.
		x = block[15]
		for i = 14; i >= 0 ; i-- {
				block[i+1] = block[i]
				// Multiplication and addition in GF.
				x = x ^ GF2_mul(block[i],L_vector[i])
		}
		block[0] = x
	}
	return block
}

func L_inv(block [16]uint8) [16]uint8 {
// Inverse of L-function.
var i,j int
var x uint8

	for j = 0; j < 16; j++ {
		x = block[0]
		for i = 0; i < 15 ; i++ {
				block[i] = block[i+1]
				x = x ^ GF2_mul(block[i],L_vector[i])
		}
		block[15] = x
	}

return block
}

func StretchKey(key [32]uint8) [10][16]uint8 {
// Stretches main key (256 bits) to 10 round keys K_1...K_10 (128 bits each).
// Feistel cipher essentially.
var i,k int
var C,x,y,z [16]uint8
var rkeys [10][16]uint8

// First - split key to pair of subkeys (K_1 = x, K_2 = y).
	for i = 0; i < 16; i++ {
		x[i] = key[i]
		y[i] = key[i + 16]
	}

	rkeys[0] = x
	rkeys[1] = y

	for i = 1; i <= 32; i++ {

			for k = range C { C[k] = 0 } // Compute C_i constants.
			C[15] = uint8(i)
			C = L(C)
			// Compute sequence of round keys.
			for k = range z { z[k] = Pi_table[(x[k] ^ C[k])] }
			z = L(z)
			for k = range z { z[k] = z[k] ^ y[k] }
			y = x
			x = z
			if i % 8 == 0 { // Store each pair of round keys.
					rkeys[(i >> 2)] = x
					rkeys[(i >> 2)+1] = y
			}
	}
	
	return rkeys
}

func GetDecryptRoundKeys(rkeys [10][16]uint8) [10][16]uint8 {
// For fast decryption (see Decrypt_K) round keys need to be L-inversed
// (except the K_0) - this allows use of in-memory lookup tables.
// This function implements inversion.
var rkeys_L [10][16]uint8
	// Calculate inverse (L function) of 9 round keys K_2..K_10.
	for k := 1; k < 10; k++ { rkeys_L[k] = L_inv(rkeys[k]) }
	rkeys_L[0] = rkeys[0]
	return rkeys_L
}

func CM_Encrypt(iv uint64, key [32]uint8, plain_text []uint8) []uint8  {
// Simple counter mode. Encrypts given plain_text with iv as a counter.
// Returns cipher text (or nil).
// Length must be 1 < len <= 2**29.
var ct []uint8
var counter_block, r_block, last_block [16]uint8
var rkeys [10][16]uint8

	if (len(plain_text) > int(2<<29)) || (len(plain_text) < 1){
		return nil
	}
	if(!CipherInitialized){
		InitCipher()
	}
	rkeys = StretchKey(key)
	
	full_block_count := len(plain_text) / 16
	tail_len := len(plain_text) - full_block_count * 16
	
	counter_block[0] = uint8(iv >> 56)
	counter_block[1] = uint8(iv >> 48)
	counter_block[2] = uint8(iv >> 40)
	counter_block[3] = uint8(iv >> 32)
	counter_block[4] = uint8(iv >> 24)
	counter_block[5] = uint8(iv >> 16)
	counter_block[6] = uint8(iv >> 8)
	counter_block[7] = uint8(iv >> 0)
	
	copy(counter_block[8:16], counter_block[0:8])
		
	for block_num := 0; block_num < full_block_count; block_num++ {
			var cb [16]uint8
			
			copy(cb[:], plain_text[(block_num*16):(block_num*16)+16])
			r_block = DoEncryptCounter(counter_block, cb, rkeys)
			
			ct = append(ct, r_block[:]...)
			iv = iv + 1
			counter_block[0] = uint8(iv >> 56)
			counter_block[1] = uint8(iv >> 48)
			counter_block[2] = uint8(iv >> 40)
			counter_block[3] = uint8(iv >> 32)
			counter_block[4] = uint8(iv >> 24)
			counter_block[5] = uint8(iv >> 16)
			counter_block[6] = uint8(iv >> 8)
			counter_block[7] = uint8(iv >> 0)
	}

	if tail_len > 0 {
			last_block = DoEncrypt(counter_block, rkeys)
			for r := 0; r < tail_len; r++ {
				ct = append(ct, plain_text[len(plain_text)-tail_len+r]^last_block[r])
			}
			
	}	
	return ct		// Cipher text.
}

func CM_Decrypt(iv uint64, key [32]uint8, c_text []uint8) []uint8  {
// Simple counter mode. Decrypts given plain_text with iv as a counter.
// Returns cipher text (or nil).
// Length must be 1 < len <= 2**29.
var pt []uint8
var counter_block, r_block, last_block [16]uint8
var rkeys [10][16]uint8

	if (len(c_text) > int(2<<29)) || (len(c_text) < 1){
		return nil
	}
	if(!CipherInitialized){
		InitCipher()
	}
	rkeys = StretchKey(key)
	
	full_block_count := len(c_text) / 16
	tail_len := len(c_text) - full_block_count * 16
	
	
	counter_block[0] = uint8(iv >> 56)
	counter_block[1] = uint8(iv >> 48)
	counter_block[2] = uint8(iv >> 40)
	counter_block[3] = uint8(iv >> 32)
	counter_block[4] = uint8(iv >> 24)
	counter_block[5] = uint8(iv >> 16)
	counter_block[6] = uint8(iv >> 8)
	counter_block[7] = uint8(iv >> 0)
	
	copy(counter_block[8:16], counter_block[0:8])
		
	for block_num := 0; block_num < full_block_count; block_num++ {
			var cb [16]uint8
			copy(cb[:], c_text[(block_num*16):(block_num*16)+16])
			r_block = DoEncryptCounter(counter_block, cb, rkeys)
			
			pt = append(pt, r_block[:]...)
			iv = iv + 1
			counter_block[0] = uint8(iv >> 56)
			counter_block[1] = uint8(iv >> 48)
			counter_block[2] = uint8(iv >> 40)
			counter_block[3] = uint8(iv >> 32)
			counter_block[4] = uint8(iv >> 24)
			counter_block[5] = uint8(iv >> 16)
			counter_block[6] = uint8(iv >> 8)
			counter_block[7] = uint8(iv >> 0)
	}

	if tail_len > 0 {
		
			last_block = DoEncrypt(counter_block, rkeys)
			for r := 0; r < tail_len; r++ {
				pt = append(pt, c_text[len(c_text)-tail_len+r]^last_block[r])
			}
	}	
	return pt		// Plain text.
}

func Encrypt(key [32]uint8, block [16]uint8) [16]uint8  {
// Encrypts block with DoEncrypt using given 256-bit key.
// Takes key and block of plain text, returns cipher text.
var ct [16]uint8
var rkeys [10][16]uint8

	if(!CipherInitialized){
		InitCipher()
	}

	rkeys = StretchKey(key) // Get round keys.
	ct = DoEncrypt(block, rkeys) // Call actual encryption procedure.

	return ct		// Cipher text.
}

func Decrypt(key [32]uint8, block [16]uint8) [16]uint8  {
// Decrypt function.
// Takes key, returns plain text (possibly).
var rkeys [10][16]uint8

	if(!CipherInitialized){
		InitCipher()
	}

	rkeys = GetDecryptRoundKeys(StretchKey(key))
	pt := DoDecrypt(block, rkeys)
	return pt // Plain text.
}

func InitCipher()  {
// Creates lookup tables for cipher runtime.
var i,j,k int
var x [16]uint8

	if(CipherInitialized){
		return
	}

	for i = 0; i < 16; i++ { // 16 bytes.
		for j = 0; j < 256; j++ { // 256 possible values of bytes - used as index.

				for k = range x { x[k] = 0 }
				x[i] = Pi_table[j]
				x = L(x)
				// This is LS lookup table, indexed by byte values.
				// LS transformation (S, then L) used in encryption.
				LS_enc_lookup[i][j] = x

				for k = range x { x[k] = 0 }
				x[i] = uint8(j)
				x = L_inv(x)
				// Inverse L lookup.
				L_inv_lookup[i][j] = x

				for k = range x { x[k] = 0 }
				x[i] = Pi_inverse_table[j]
				x = L_inv(x)
				// SL inverse transformation used in decryption.
				SL_dec_lookup[i][j] = x

			}
	}
	CipherInitialized = true
	return
}


// Standard error-info construction (from crypto/aes)
type KeySizeError int
func (k KeySizeError) Error() string {
	return "Kuznyechik cipher: invalid key size! Must be 32 bytes!"
}

func NewCipher(key []byte) (cipher.Block, error) {
// Function to create a new cipher.
// While using with crypto/cipher we need to create cipher.Block to pass as
// block cipher to GCM mode routines (see test_grasshoopper.go for examples).
var t_key [32]uint8 // Local copy of key.

	if len(key) != 32 { // Only 256 bits!
		return nil, KeySizeError(len(key))
	}

	c := *(new(GOSThopper))
	copy(t_key[:],key[:32])
	// Encryption and decryption round keys are somewhat different (see above).
	c.enc_keys = StretchKey(t_key)
	c.dec_keys = GetDecryptRoundKeys(c.enc_keys)
	if(!CipherInitialized){
						InitCipher() // Create lookup tables.
					}
	return &c, nil
}

func (c *GOSThopper) BlockSize() int {
// Interface for cipher.Block. Returns block size of cipher.
	return BlockSize
}

func (c *GOSThopper) Encrypt(dst, src []byte) {
// Encrypts given block src into dst with current round keys.
var ct_block [16]uint8

	if len(src) < BlockSize {
		panic("Kuznyechik cipher: input length less than full block!")
	}
	if len(dst) < BlockSize {
		panic("Kuznyechik cipher: output length less than full block!")
	}
	copy(ct_block[:],src[:16])
	ct_block = DoEncrypt(ct_block, c.enc_keys)
	copy(dst,ct_block[:])

}

func (c *GOSThopper) Decrypt(dst, src []byte){
// Decrypts given block src into dst.
var pt_block [16]uint8

		if len(src) < BlockSize {
			panic("Kuznyechik cipher: input length less than full block!")
		}
		if len(dst) < BlockSize {
			panic("Kuznyechik cipher: output length less than full block!")
		}

	copy(pt_block[:],src[:16])
	pt_block = DoDecrypt(pt_block, c.dec_keys)
	copy(dst,pt_block[:])

}
