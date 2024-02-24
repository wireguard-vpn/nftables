package expr

import (
	"encoding/binary"

	"github.com/google/nftables/binaryutil"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type CheckOp uint32

const (
	CheckOpPort = 0
	CheckOpTTL  = 1
)

type VPNCheckNA uint32

const (
	NFTA_CLEVERVPN_REG_PORT = 1
	NFTA_CLEVERVPN_REG_TTL  = 2
	NFTA_CLEVERVPN_OP       = 3
)

type VPNCheck struct {
	PortRegister uint32
	TTLRegister  uint32
	Op           CheckOp
}

func (e *VPNCheck) marshal(fam byte) ([]byte, error) {

	exprData, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: NFTA_CLEVERVPN_REG_PORT, Data: binaryutil.BigEndian.PutUint32(e.PortRegister)},
		{Type: NFTA_CLEVERVPN_REG_TTL, Data: binaryutil.BigEndian.PutUint32(e.TTLRegister)},
		{Type: NFTA_CLEVERVPN_OP, Data: binaryutil.BigEndian.PutUint32(uint32(e.Op))},
	})
	if err != nil {
		return nil, err
	}
	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("clevervpncheck\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: exprData},
	})
}

func (e *VPNCheck) unmarshal(fam byte, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case NFTA_CLEVERVPN_REG_PORT:
			e.PortRegister = ad.Uint32()
		case NFTA_CLEVERVPN_REG_TTL:
			e.TTLRegister = ad.Uint32()
		case NFTA_CLEVERVPN_OP:
			e.Op = CheckOp(ad.Uint32())
		}
	}
	return ad.Err()
}
