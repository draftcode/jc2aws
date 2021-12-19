// Copyright 2021 Masaya Suzuki
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package fido2 is a stripped version of go-libfido2.
//
// Unfortunately, Ubuntu 20.04 comes with an old libfido2, is not compatible
// with any releases of go-libfido2. This package is basically a copy of
// https://github.com/keys-pub/go-libfido2/blob/master/fido2.go.
package fido2

// #cgo pkg-config: libfido2
//
// #include <fido.h>
// #include <stdlib.h>
import "C"
import (
	"fmt"
	"unsafe"
)

func init() {
	C.fido_init(0)
}

const maxDevices = 64

type Assertion struct {
	AuthDataCBOR []byte
	Sig          []byte
}

func DeviceLocations() ([]string, error) {
	cMax := C.size_t(maxDevices)
	info := C.fido_dev_info_new(cMax)
	var cFound C.size_t = 0
	cErr := C.fido_dev_info_manifest(info, cMax, &cFound)
	if cErr != C.FIDO_OK {
		return nil, fmt.Errorf("fido_dev_info_manifest returns an error: %v", cErr)
	}
	defer C.fido_dev_info_free(&info, C.size_t(maxDevices))
	found := int(cFound)

	var locs []string
	for i := 0; i < found; i++ {
		devInfo := C.fido_dev_info_ptr(info, C.size_t(i))
		if devInfo == nil {
			return nil, fmt.Errorf("fido_dev_info_ptr returns nil")
		}
		locs = append(locs, C.GoString(C.fido_dev_info_path(devInfo)))
	}
	return locs, nil
}

func NewAssertion(loc, rpID string, clientDataHash []byte, credentialIDs [][]byte) (*Assertion, error) {
	dev := C.fido_dev_new()
	if cErr := C.fido_dev_open(dev, C.CString(loc)); cErr != C.FIDO_OK {
		return nil, fmt.Errorf("fido_dev_open returns an error: %v", cErr)
	}
	defer C.fido_dev_close(dev)

	cAssert := C.fido_assert_new()
	defer C.fido_assert_free(&cAssert)

	if cErr := C.fido_assert_set_rp(cAssert, C.CString(rpID)); cErr != C.FIDO_OK {
		return nil, fmt.Errorf("fido_assert_set_rp returns an error: %v", cErr)
	}
	if cErr := C.fido_assert_set_clientdata_hash(cAssert, cBytes(clientDataHash), cLen(clientDataHash)); cErr != C.FIDO_OK {
		return nil, fmt.Errorf("fido_assert_set_clientdata_hash returns an error: %v", cErr)
	}
	for _, credentialID := range credentialIDs {
		if cErr := C.fido_assert_allow_cred(cAssert, cBytes(credentialID), cLen(credentialID)); cErr != C.FIDO_OK {
			return nil, fmt.Errorf("fido_assert_allow_cred returns an error: %v", cErr)
		}
	}
	if cErr := C.fido_dev_get_assert(dev, cAssert, nil); cErr != C.FIDO_OK {
		return nil, fmt.Errorf("fido_dev_get_assert returns an error: %v", cErr)
	}

	cIdx := C.size_t(0)
	cAuthDataLen := C.fido_assert_authdata_len(cAssert, cIdx)
	cAuthDataPtr := C.fido_assert_authdata_ptr(cAssert, cIdx)
	authDataCBOR := C.GoBytes(unsafe.Pointer(cAuthDataPtr), C.int(cAuthDataLen))

	cSigLen := C.fido_assert_sig_len(cAssert, cIdx)
	cSigPtr := C.fido_assert_sig_ptr(cAssert, cIdx)
	sig := C.GoBytes(unsafe.Pointer(cSigPtr), C.int(cSigLen))
	return &Assertion{
		AuthDataCBOR: authDataCBOR,
		Sig:          sig,
	}, nil
}

func cBytes(b []byte) *C.uchar {
	return (*C.uchar)(&[]byte(b)[0])
}

func cLen(b []byte) C.size_t {
	return C.size_t(len(b))
}
