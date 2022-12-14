/*
Package v1alpha1 is a generated protocol buffer package.

It is generated from these files:

	service.proto

It has these top-level messages:

	SignPayloadRequest
	SignPayloadResponse
	PublicKey
	ListPublicKeysRequest
	ListPublicKeysResponse
*/
package v1alpha1

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

type SignPayloadRequest struct {
	// payload is the content to be signed
	Payload []byte `protobuf:"bytes,1,opt,name=payload,proto3" json:"payload,omitempty"`
	// algorithm specifies which algorithm to sign with
	Algorithm string `protobuf:"bytes,2,opt,name=algorithm,proto3" json:"algorithm,omitempty"`
}

func (m *SignPayloadRequest) Reset()                    { *m = SignPayloadRequest{} }
func (m *SignPayloadRequest) String() string            { return proto.CompactTextString(m) }
func (*SignPayloadRequest) ProtoMessage()               {}
func (*SignPayloadRequest) Descriptor() ([]byte, []int) { return fileDescriptorService, []int{0} }

func (m *SignPayloadRequest) GetPayload() []byte {
	if m != nil {
		return m.Payload
	}
	return nil
}

func (m *SignPayloadRequest) GetAlgorithm() string {
	if m != nil {
		return m.Algorithm
	}
	return ""
}

type SignPayloadResponse struct {
	// content returns the signed payload
	Content []byte `protobuf:"bytes,1,opt,name=content,proto3" json:"content,omitempty"`
}

func (m *SignPayloadResponse) Reset()                    { *m = SignPayloadResponse{} }
func (m *SignPayloadResponse) String() string            { return proto.CompactTextString(m) }
func (*SignPayloadResponse) ProtoMessage()               {}
func (*SignPayloadResponse) Descriptor() ([]byte, []int) { return fileDescriptorService, []int{1} }

func (m *SignPayloadResponse) GetContent() []byte {
	if m != nil {
		return m.Content
	}
	return nil
}

type PublicKey struct {
	// public_key is a PEM encoded public key
	PublicKey []byte `protobuf:"bytes,1,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	// certificate is a concatenated list of PEM encoded x509 certificates
	Certificates []byte `protobuf:"bytes,2,opt,name=certificates,proto3" json:"certificates,omitempty"`
	// key_id is the key's ID
	KeyId string `protobuf:"bytes,3,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty"`
	// algorithm states the algorithm the key uses
	Algorithm string `protobuf:"bytes,4,opt,name=algorithm,proto3" json:"algorithm,omitempty"`
}

func (m *PublicKey) Reset()                    { *m = PublicKey{} }
func (m *PublicKey) String() string            { return proto.CompactTextString(m) }
func (*PublicKey) ProtoMessage()               {}
func (*PublicKey) Descriptor() ([]byte, []int) { return fileDescriptorService, []int{2} }

func (m *PublicKey) GetPublicKey() []byte {
	if m != nil {
		return m.PublicKey
	}
	return nil
}

func (m *PublicKey) GetCertificates() []byte {
	if m != nil {
		return m.Certificates
	}
	return nil
}

func (m *PublicKey) GetKeyId() string {
	if m != nil {
		return m.KeyId
	}
	return ""
}

func (m *PublicKey) GetAlgorithm() string {
	if m != nil {
		return m.Algorithm
	}
	return ""
}

type ListPublicKeysRequest struct {
}

func (m *ListPublicKeysRequest) Reset()                    { *m = ListPublicKeysRequest{} }
func (m *ListPublicKeysRequest) String() string            { return proto.CompactTextString(m) }
func (*ListPublicKeysRequest) ProtoMessage()               {}
func (*ListPublicKeysRequest) Descriptor() ([]byte, []int) { return fileDescriptorService, []int{3} }

type ListPublicKeysResponse struct {
	// active_key_id is the active signing key's ID
	ActiveKeyId string `protobuf:"bytes,1,opt,name=active_key_id,json=activeKeyId,proto3" json:"active_key_id,omitempty"`
	// public_keys is a list of public verifying keys
	PublicKeys []*PublicKey `protobuf:"bytes,2,rep,name=public_keys,json=publicKeys" json:"public_keys,omitempty"`
}

func (m *ListPublicKeysResponse) Reset()                    { *m = ListPublicKeysResponse{} }
func (m *ListPublicKeysResponse) String() string            { return proto.CompactTextString(m) }
func (*ListPublicKeysResponse) ProtoMessage()               {}
func (*ListPublicKeysResponse) Descriptor() ([]byte, []int) { return fileDescriptorService, []int{4} }

func (m *ListPublicKeysResponse) GetActiveKeyId() string {
	if m != nil {
		return m.ActiveKeyId
	}
	return ""
}

func (m *ListPublicKeysResponse) GetPublicKeys() []*PublicKey {
	if m != nil {
		return m.PublicKeys
	}
	return nil
}

func init() {
	proto.RegisterType((*SignPayloadRequest)(nil), "v1alpha1.SignPayloadRequest")
	proto.RegisterType((*SignPayloadResponse)(nil), "v1alpha1.SignPayloadResponse")
	proto.RegisterType((*PublicKey)(nil), "v1alpha1.PublicKey")
	proto.RegisterType((*ListPublicKeysRequest)(nil), "v1alpha1.ListPublicKeysRequest")
	proto.RegisterType((*ListPublicKeysResponse)(nil), "v1alpha1.ListPublicKeysResponse")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for KeyService service

type KeyServiceClient interface {
	// Sign an incoming payload
	SignPayload(ctx context.Context, in *SignPayloadRequest, opts ...grpc.CallOption) (*SignPayloadResponse, error)
	// List all active public keys
	ListPublicKeys(ctx context.Context, in *ListPublicKeysRequest, opts ...grpc.CallOption) (*ListPublicKeysResponse, error)
}

type keyServiceClient struct {
	cc *grpc.ClientConn
}

func NewKeyServiceClient(cc *grpc.ClientConn) KeyServiceClient {
	return &keyServiceClient{cc}
}

func (c *keyServiceClient) SignPayload(ctx context.Context, in *SignPayloadRequest, opts ...grpc.CallOption) (*SignPayloadResponse, error) {
	out := new(SignPayloadResponse)
	err := grpc.Invoke(ctx, "/v1alpha1.KeyService/SignPayload", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyServiceClient) ListPublicKeys(ctx context.Context, in *ListPublicKeysRequest, opts ...grpc.CallOption) (*ListPublicKeysResponse, error) {
	out := new(ListPublicKeysResponse)
	err := grpc.Invoke(ctx, "/v1alpha1.KeyService/ListPublicKeys", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for KeyService service

type KeyServiceServer interface {
	// Sign an incoming payload
	SignPayload(context.Context, *SignPayloadRequest) (*SignPayloadResponse, error)
	// List all active public keys
	ListPublicKeys(context.Context, *ListPublicKeysRequest) (*ListPublicKeysResponse, error)
}

func RegisterKeyServiceServer(s *grpc.Server, srv KeyServiceServer) {
	s.RegisterService(&_KeyService_serviceDesc, srv)
}

func _KeyService_SignPayload_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SignPayloadRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyServiceServer).SignPayload(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/v1alpha1.KeyService/SignPayload",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyServiceServer).SignPayload(ctx, req.(*SignPayloadRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyService_ListPublicKeys_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListPublicKeysRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyServiceServer).ListPublicKeys(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/v1alpha1.KeyService/ListPublicKeys",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyServiceServer).ListPublicKeys(ctx, req.(*ListPublicKeysRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _KeyService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "v1alpha1.KeyService",
	HandlerType: (*KeyServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SignPayload",
			Handler:    _KeyService_SignPayload_Handler,
		},
		{
			MethodName: "ListPublicKeys",
			Handler:    _KeyService_ListPublicKeys_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "service.proto",
}

func init() { proto.RegisterFile("service.proto", fileDescriptorService) }

var fileDescriptorService = []byte{
	// 316 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x74, 0x52, 0x4d, 0x4f, 0x02, 0x31,
	0x10, 0x75, 0x45, 0xd1, 0x9d, 0x05, 0x0f, 0x25, 0xe8, 0x86, 0x40, 0x24, 0x3d, 0x71, 0xc2, 0x80,
	0xfe, 0x09, 0x03, 0x07, 0xb2, 0xc4, 0x33, 0x29, 0x65, 0x84, 0x86, 0x75, 0x5b, 0xb7, 0x85, 0xa4,
	0x67, 0x7f, 0x91, 0xff, 0xd0, 0xd0, 0xfd, 0x12, 0x94, 0xe3, 0xbc, 0xe9, 0xbc, 0x79, 0xef, 0x4d,
	0xa1, 0xa9, 0x31, 0xdd, 0x0b, 0x8e, 0x43, 0x95, 0x4a, 0x23, 0xc9, 0xed, 0x7e, 0xc4, 0x62, 0xb5,
	0x61, 0x23, 0x3a, 0x05, 0x32, 0x17, 0xeb, 0x64, 0xc6, 0x6c, 0x2c, 0xd9, 0x2a, 0xc2, 0xcf, 0x1d,
	0x6a, 0x43, 0x42, 0xb8, 0x51, 0x19, 0x12, 0x7a, 0x7d, 0x6f, 0xd0, 0x88, 0x8a, 0x92, 0x74, 0xc1,
	0x67, 0xf1, 0x5a, 0xa6, 0xc2, 0x6c, 0x3e, 0xc2, 0xcb, 0xbe, 0x37, 0xf0, 0xa3, 0x0a, 0xa0, 0x4f,
	0xd0, 0x3a, 0x62, 0xd3, 0x4a, 0x26, 0x1a, 0x0f, 0x74, 0x5c, 0x26, 0x06, 0x13, 0x53, 0xd0, 0xe5,
	0x25, 0xfd, 0xf2, 0xc0, 0x9f, 0xed, 0x96, 0xb1, 0xe0, 0x13, 0xb4, 0xa4, 0x07, 0xa0, 0x5c, 0xb1,
	0xd8, 0xa2, 0xcd, 0x9f, 0xfa, 0xaa, 0x6c, 0x53, 0x68, 0x70, 0x4c, 0x8d, 0x78, 0x17, 0x9c, 0x19,
	0xd4, 0x6e, 0x7d, 0x23, 0x3a, 0xc2, 0x48, 0x1b, 0xea, 0x5b, 0xb4, 0x0b, 0xb1, 0x0a, 0x6b, 0x4e,
	0xdc, 0xf5, 0x16, 0xed, 0xeb, 0x89, 0xec, 0xab, 0x53, 0xd9, 0x0f, 0xd0, 0x9e, 0x0a, 0x6d, 0x4a,
	0x21, 0x3a, 0xcf, 0x81, 0xa6, 0x70, 0x7f, 0xda, 0xc8, 0x2d, 0x51, 0x68, 0x32, 0x6e, 0xc4, 0x1e,
	0x17, 0xf9, 0x3a, 0xcf, 0x91, 0x06, 0x19, 0x38, 0x71, 0x4b, 0x5f, 0x20, 0xa8, 0xec, 0x1c, 0xe4,
	0xd6, 0x06, 0xc1, 0xb8, 0x35, 0x2c, 0xb2, 0x1f, 0x96, 0xb4, 0x11, 0x94, 0x26, 0xf5, 0xf8, 0xdb,
	0x03, 0x98, 0xa0, 0x9d, 0x67, 0x07, 0x23, 0x53, 0x08, 0x7e, 0x45, 0x4a, 0xba, 0xd5, 0xf8, 0xdf,
	0xbb, 0x75, 0x7a, 0x67, 0xba, 0x99, 0x68, 0x7a, 0x41, 0xde, 0xe0, 0xee, 0xd8, 0x10, 0x79, 0xac,
	0x46, 0xfe, 0xcd, 0xa0, 0xd3, 0x3f, 0xff, 0xa0, 0xa0, 0x5d, 0xd6, 0xdd, 0xb7, 0x7a, 0xfe, 0x09,
	0x00, 0x00, 0xff, 0xff, 0x8c, 0x5a, 0xf9, 0x01, 0x67, 0x02, 0x00, 0x00,
}
