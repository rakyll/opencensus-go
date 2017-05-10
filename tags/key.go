package tags

// KeyType defines the types of keys allowed.
type keyType byte

const (
	keyInt64 keyType = iota
	keyBool
	keyString
)

// Key is the interface for all key types.
type Key interface {
	Name() string
	ID() int32
	Type() keyType
}

// KeyString is the interface for keys which values are of type string.
type KeyString interface {
	Key
	CreateTagOp(v string, op TagOp) *ChangeString
	CreateTag(v string) *tagString
}

// KeyBytes is the interface for keys which values are of type []byte.
type KeyBytes interface {
	Key
	CreateTagOp(v []byte, op TagOp) *ChangeBytes
	CreateTag(v []byte) *tagBytes
}

// KeyBool is the interface for keys which values are of type bool.
type KeyBool interface {
	Key
	CreateTagOp(v bool, op TagOp) *ChangeBool
	CreateTag(v bool) *tagBool
}

// KeyInt64 is the interface for keys which values are of type int64.
type KeyInt64 interface {
	Key
	CreateTagOp(v int64, op TagOp) *ChangeInt64
	CreateTag(v int64) *tagInt64
}
