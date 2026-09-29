package avb

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
)

// LoadKey reads an RSA private key in PKCS#1 or PKCS#8 PEM form with a 2048, 4096 or 8192-bit modulus and exponent 65537.
func LoadKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		var parsed any
		if parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			var ok bool
			if key, ok = parsed.(*rsa.PrivateKey); !ok {
				err = errors.New("not an RSA key")
			}
		}
	default:
		err = fmt.Errorf("unsupported PEM block %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if bits := key.N.BitLen(); (bits != 2048 && bits != 4096 && bits != 8192) || key.E != 65537 {
		return nil, fmt.Errorf("%s: AVB needs a 2048, 4096 or 8192-bit RSA key with exponent 65537, got %d bits and exponent %d", path, bits, key.E)
	}
	return key, nil
}

// PublicKeyBlob encodes key as libavb's AvbRSAPublicKeyHeader: bit count, n0inv = -1/n mod 2^32, modulus and R^2 mod n.
func PublicKeyBlob(key *rsa.PublicKey) []byte {
	bits := key.N.BitLen()
	base := new(big.Int).Lsh(big.NewInt(1), 32)
	n0inv := new(big.Int).Sub(base, new(big.Int).ModInverse(new(big.Int).Mod(key.N, base), base))
	r := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	rr := new(big.Int).Mod(new(big.Int).Mul(r, r), key.N)
	blob := make([]byte, 8+2*bits/8)
	binary.BigEndian.PutUint32(blob, uint32(bits))
	binary.BigEndian.PutUint32(blob[4:], uint32(n0inv.Uint64()))
	key.N.FillBytes(blob[8 : 8+bits/8])
	rr.FillBytes(blob[8+bits/8:])
	return blob
}

// parsePublicKeyBlob recovers the RSA modulus from an AvbRSAPublicKeyHeader blob.
func parsePublicKeyBlob(blob []byte) (*rsa.PublicKey, error) {
	if len(blob) < 8 {
		return nil, errors.New("public key blob too short")
	}
	bits := int(binary.BigEndian.Uint32(blob))
	if bits%8 != 0 || len(blob) != 8+2*bits/8 {
		return nil, fmt.Errorf("public key blob of %d bytes does not hold a %d-bit key", len(blob), bits)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(blob[8 : 8+bits/8]), E: 65537}, nil
}

// verifySignature checks the vbmeta signature with the public key embedded in the blob.
func verifySignature(algorithm uint32, digest, signature, publicKey []byte) bool {
	key, err := parsePublicKeyBlob(publicKey)
	if err != nil || algorithm < 1 || algorithm > 6 {
		return false
	}
	hash := crypto.SHA256
	if algorithm >= 4 {
		hash = crypto.SHA512
	}
	return rsa.VerifyPKCS1v15(key, hash, digest, signature) == nil
}

func roundUp(value, unit int) int { return (value + unit - 1) / unit * unit }

// chainDescriptor rebuilds a chain partition descriptor around a new public key.
func chainDescriptor(raw, publicKey []byte) []byte {
	be := binary.BigEndian
	body := raw[16:]
	name := body[76 : 76+be.Uint32(body[4:])]
	fixed := bytes.Clone(body[:76])
	be.PutUint32(fixed[8:], uint32(len(publicKey)))
	payload := append(append(fixed, name...), publicKey...)
	payload = append(payload, make([]byte, roundUp(len(payload), 8)-len(payload))...)
	out := make([]byte, 16, 16+len(payload))
	be.PutUint64(out, 4)
	be.PutUint64(out[8:], uint64(len(payload)))
	return append(out, payload...)
}

// Sign re-encodes a vbmeta blob signed by key with avbtool's block layout. The hash family of the original algorithm is
// kept (SHA256 when it was unsigned), chain descriptors named in chains take the given public keys, and the rollback
// index, flags, release string and public key metadata stay as they were.
func Sign(blob []byte, key *rsa.PrivateKey, chains map[string][]byte) ([]byte, error) {
	spans, err := descriptorSpans(blob)
	if err != nil {
		return nil, err
	}
	be := binary.BigEndian
	header := bytes.Clone(blob[:HeaderSize])
	aux := blob[HeaderSize+int(be.Uint64(blob[12:])):]
	metadata := aux[be.Uint64(header[80:]) : be.Uint64(header[80:])+be.Uint64(header[88:])]
	var descriptors []byte
	for _, item := range spans {
		raw := blob[item.start:item.end]
		if item.tag == 4 {
			name := string(raw[16+76 : 16+76+be.Uint32(raw[16+4:])])
			if publicKey, ok := chains[name]; ok {
				raw = chainDescriptor(raw, publicKey)
			}
		}
		descriptors = append(descriptors, raw...)
	}
	bits := key.N.BitLen()
	algorithm, hash, hashSize := uint32(1), crypto.SHA256, 32
	if old := be.Uint32(header[28:]); old >= 4 && old <= 6 {
		algorithm, hash, hashSize = 4, crypto.SHA512, 64
	}
	algorithm += map[int]uint32{2048: 0, 4096: 1, 8192: 2}[bits]
	publicKey := PublicKeyBlob(&key.PublicKey)
	auxBlock := append(append(append([]byte{}, descriptors...), publicKey...), metadata...)
	auxBlock = append(auxBlock, make([]byte, roundUp(len(auxBlock), 64)-len(auxBlock))...)
	signatureSize := bits / 8
	authSize := roundUp(hashSize+signatureSize, 64)
	for offset, value := range map[int]uint64{12: uint64(authSize), 20: uint64(len(auxBlock)), 32: 0, 40: uint64(hashSize), 48: uint64(hashSize), 56: uint64(signatureSize), 64: uint64(len(descriptors)), 72: uint64(len(publicKey)), 80: uint64(len(descriptors) + len(publicKey)), 88: uint64(len(metadata)), 96: 0, 104: uint64(len(descriptors))} {
		be.PutUint64(header[offset:], value)
	}
	be.PutUint32(header[28:], algorithm)
	digest := vbmetaDigest(algorithm, header, auxBlock)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, hash, digest)
	if err != nil {
		return nil, fmt.Errorf("sign vbmeta: %w", err)
	}
	auth := make([]byte, authSize)
	copy(auth, digest)
	copy(auth[hashSize:], signature)
	return append(append(header, auth...), auxBlock...), nil
}
