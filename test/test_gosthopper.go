// Various tests and examples for block cipher Kuznechik, GOST R 34.12-2015, implementation.
// Includes part with GCM: AEAD mode for cipher.
// Author: Alexander Venedioukhin, https://dxdt.ru/
// Date: 17/02/2019
// Free software, distribution unlimited.

package main

import (
	"dxdt.ru/gosthopper"
	"crypto/cipher"
	"fmt"
	"time"
	"bytes"
	"math/rand"
)

func main() {

// Test vectors.
// Standard test key.
var test_K = [32]uint8 { 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                         0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }
// Standard test plain text block and corresponding cipher text.
var test_PT = [16]uint8 { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 }
var reference_CT = [16]uint8 { 0x7F,0x67, 0x9D, 0x90, 0xBE, 0xBC, 0x24, 0x30, 0x5A, 0x46, 0x8D, 0x42, 0xB9, 0xD4, 0xED, 0xCD }
// Additional key, one bit changed test_K.
var test_K1 = [32]uint8 { 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                         0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcf, 0xef }
// Example key (non-standard).
var example_K = [32]uint8 { 0x17, 0x19, 0xca, 0xfe, 0x0c, 0x10, 0x03, 0x15, 0x2d, 0x19, 0x27, 0x13, 0x07, 0xab, 0x71, 0x67,
                         0x1f, 0xe9, 0xa7, 0x31, 0x87, 0x15, 0x78, 0x61, 0x65, 0x03, 0x01, 0xef, 0x4a, 0xec, 0x9f, 0xf3 }

// Test vectors for GCM.
var var_K = []byte { 0x31, 0x89, 0x9a, 0x7e, 0x1a, 0x03, 0x03, 0x51, 0xd2, 0x97, 0x79, 0x3b, 0x7f, 0xaf, 0xfe, 0x71,
					 0xff, 0xe0, 0xca, 0x13, 0x42, 0x5e, 0x99, 0x77, 0x6b, 0xd3, 0xee, 0x11, 0xba, 0xc7, 0x92, 0x8f }
var GCM_nonce = []byte { 0x3c, 0x81, 0x9d, 0x9a, 0x9b, 0xed, 0x08, 0x76, 0x15, 0x03, 0x0b, 0x65 }
var GCM_example_AD = []byte { 'T','O',':',' ','S','e','a','p','o','r','t',',',' ','a','g','e','n','t',' ','Z','o','r','k','a'}
var GCM_example_AD_m = []byte { 'T','O',':',' ','S','e','a','p','o','r','t',',',' ','a','g','e','n','t',' ','D','a','s','h','a'}
var GCM_example_PT = []byte { 'S','e','a','r','c','h',' ','t','h','e',' ','b','i','g',' ','w','h','i','t','e',' ','s','h','i','p','.' }
// Test text for counter mode.
var CounterMode_example_PT = "The hunter will softly and suddenly vanish away, and never be met with again."
// Non-standard example plain text.
var example_PT = [16]uint8 { 'S','e','a','r','c','h',' ','t','h','e',' ','s','h','i','p','.' }
// 16 blocks used in simple performance test.
var rand_PT [16][16]uint8

// For performance test we use non-standard test vector as a key - example_K.
rkeys := gosthopper.StretchKey(example_K) // Generate round keys for encryption.
dec_rkeys := gosthopper.GetDecryptRoundKeys(rkeys) // Generate round keys for decryption.

gosthopper.InitCipher() // Generate lookup tables.

fmt.Printf("\nGOST R 34.12-2015 test\n\n")
fmt.Printf("| Standard test key:\n| %X\n| Standard test plain text:\n| %X\n\n", test_K, test_PT)
fmt.Printf("---\n\n(1) Standard key vector\n")

test_CT := gosthopper.Encrypt(test_K,test_PT)
fmt.Printf("(1.1) Plain text:\t\t\t%X\n(1.2) Cipher text:\t\t\t%X - ", test_PT, test_CT)
if(test_CT != reference_CT){
	fmt.Printf("FAILED! [Not equal to reference cipher text!]\n")
}else{
	fmt.Printf("OK\n");
}

test_2PT := gosthopper.Decrypt(test_K,test_CT)
fmt.Printf("(1.3) Plain text decrypted:\t\t%X - ", test_2PT)

if(test_2PT != test_PT){
	fmt.Printf("FAILED! [PT != D(E(PT,K),K)]\n")
}else{
	fmt.Printf("OK\n")
}

fmt.Printf("---\n\n(1a) Incorrect key test\n")
test_2PT1 := gosthopper.Decrypt(test_K1,test_CT)
fmt.Printf("(1a.1) Plain text decrypted (key_1):\t%X - ", test_2PT1)

if(test_2PT1 != test_PT){
	fmt.Printf("OK (different plain text)\n")
}else{
	fmt.Printf("FAILED!\n")
}


fmt.Printf("\n\n(2) Example key and plain text vectors.\n\n")
test_CT = gosthopper.DoEncrypt(example_PT,rkeys)
fmt.Printf("(2.1)(Low level DoEncrypt) Cipher text:\t%X\n", test_CT)

test_2PT = gosthopper.DoDecrypt(test_CT,dec_rkeys)
fmt.Printf("(2.2)(Low level DoDecrypt) Plain text:\t")
if(example_PT != test_2PT){
	fmt.Printf("- FAILED! [Not equal to reference plain text!]\n")
}else{
	fmt.Printf("%s - OK\n", test_2PT)
}

test_3PT := gosthopper.Decrypt(example_K,test_CT)
fmt.Printf("(2.3)(Decrypt) Plain text:\t\t",)
if(example_PT != test_3PT){
	fmt.Printf(" - FAILED! [Not equal to reference plain text!]\n")
}else{
	fmt.Printf("%s - OK\n", test_3PT);
}

fmt.Printf("\n\n(3) Simple counter mode.\n\n")
CM_CipherText := gosthopper.CM_Encrypt(0x1234567, example_K, []uint8(CounterMode_example_PT))
CM_PlainText := gosthopper.CM_Decrypt(0x1234567, example_K, CM_CipherText)

fmt.Printf("Source PT:\n\t%s\nEncrypted:\n\t%0X\nDecrypted:\n\t%0X\n", CounterMode_example_PT,CM_CipherText,CM_PlainText)

fc_flag := true

if(len(CM_PlainText) != len([]uint8(CounterMode_example_PT))){
	fc_flag = false
}else{
	for l := range CM_PlainText{
		if(CM_PlainText[l] != uint8(CounterMode_example_PT[l])){
			fc_flag = false;
			break;
		}
	}
}
if fc_flag {
	fmt.Printf("\t(%s)\n",CM_PlainText)
}
fmt.Printf("\n(3.1) Counter mode test - ")
if !fc_flag {
	fmt.Printf("FAILED! [Not equal to source plain text!]\n")
}else{
	fmt.Printf("OK\n");
}

fmt.Printf("\n---\n")

fmt.Printf("\nTesting GCM (and cipher.Block interface) implementation.\n")

kCipher, err := gosthopper.NewCipher(var_K)
if(err != nil) {

	fmt.Printf("NewCipher failed!\n")

}

kuznecGCM, err := cipher.NewGCM(kCipher)
if(err != nil) {

	fmt.Printf("NewGCM failed!\n")

}

GCM_sealed := kuznecGCM.Seal(nil, GCM_nonce, GCM_example_PT, GCM_example_AD)

fmt.Printf("GCM:\n Plain text: %s\n Additional Data: %s\n Nonce: %X\n Encryption result (CT+Tag): %X\n", GCM_example_PT, GCM_example_AD, GCM_nonce, GCM_sealed)

GCM_opened, err := kuznecGCM.Open(nil, GCM_nonce, GCM_sealed, GCM_example_AD)

fmt.Printf(" GCM open result: %s - ", GCM_opened)
if !bytes.Equal(GCM_opened,GCM_example_PT) {
	fmt.Printf("FAILED! [Not equal to reference plain text!]\n")
}else{
	fmt.Printf("OK\n");
}

fmt.Printf(" GCM Manipulated AD check result: ")

GCM_opened, err = kuznecGCM.Open(nil, GCM_nonce, GCM_sealed, GCM_example_AD_m)

if (err != nil) {
	fmt.Printf(" [decryption failed] - OK (correct: must fail!)\n")
} else {
	fmt.Printf(" [decrypted] - FAILED!\n")
}

fmt.Printf("\n---\n\nMeasuring speed.\nSimple block operations (DoEncrypt()/DoDecrypt()):\n")

PRNG := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))

for i := 0; i < 16; i++ {
	for t := range rand_PT[i] { rand_PT[i][t] = uint8(PRNG.Uint32()) }
}

measure_start := time.Now()
var counter int = 0

for i := 0; i < 2300000; i++ {
		for t := range rand_PT {
				test_CT = gosthopper.DoEncrypt(rand_PT[t],rkeys)
				counter++
		}
}

elapsed := time.Since(measure_start)
eSec := int(elapsed.Seconds())

fmt.Printf(" Encryption - %d blocks (%d cbytes), time: %s", counter, counter*16, elapsed)
if eSec > 0 {
	fmt.Printf(" (~%d MB/sec)\n", ((counter*16)/eSec/1048576))
} else {
	fmt.Printf("\n")
}

measure_start = time.Now()

counter = 0

for i := 0; i < 2300000; i++ {
		for t := range rand_PT {
				test_CT = gosthopper.DoDecrypt(rand_PT[t],dec_rkeys)
				counter++
		}
}

elapsed = time.Since(measure_start)
eSec = int(elapsed.Seconds())

fmt.Printf(" Decryption - %d blocks (%d bytes), time: %s", counter, counter*16, elapsed)
if eSec > 0 {
	fmt.Printf(" (~%d MB/sec)\n", ((counter*16)/eSec/1048576))
} else {
	fmt.Printf("\n")
}

fmt.Printf("Kuznyechik-GCM:\n")
LongBuffer := make([]byte,1048576)
LongResult := make([]byte,1048576)

for t := range LongBuffer { LongBuffer[t] = byte(PRNG.Uint32()) }

measure_start = time.Now()

for i := 0; i < 100; i++ {

	for k := range GCM_nonce { GCM_nonce[k] = byte(PRNG.Uint32()) }
	res_buf := kuznecGCM.Seal(nil, GCM_nonce, LongBuffer, GCM_example_AD)
	LongResult, err = kuznecGCM.Open(nil, GCM_nonce, res_buf, GCM_example_AD)
	if(err != nil) {
		fmt.Printf("GCM.Open Failed!\n")
	}
	if !bytes.Equal(LongBuffer,LongResult) {
		fmt.Printf("Failed: decrypted cipher text is not equal to source plain text!\n")
	}
}

elapsed = time.Since(measure_start)
eSec = int(elapsed.Seconds())
fmt.Printf(" 100 encrypt/decrypt operations on 10M buffer, time: %s", elapsed)
if eSec > 0 {
	fmt.Printf(" (~%d MB/sec)\n", (200/eSec))
} else {
	fmt.Printf("\n")
}

fmt.Printf("\nDone!\n\n")

 }
