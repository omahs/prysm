package validator

import (
	"context"
	"fmt"

	"github.com/prysmaticlabs/prysm/v3/beacon-chain/core/transition/interop"
	"github.com/prysmaticlabs/prysm/v3/config/params"
	consensusblocks "github.com/prysmaticlabs/prysm/v3/consensus-types/blocks"
	"github.com/prysmaticlabs/prysm/v3/encoding/bytesutil"
	ethpb "github.com/prysmaticlabs/prysm/v3/proto/prysm/v1alpha1"
)

func (vs *Server) getCapellaBeaconBlock(ctx context.Context, req *ethpb.BlockRequest) (*ethpb.GenericBeaconBlock, error) {
	altairBlk, err := vs.BuildAltairBeaconBlock(ctx, req)
	if err != nil {
		return nil, err
	}

	if !req.SkipMevBoost {
		if mevBoostBlock := vs.registerMevBoost(ctx, req, altairBlk); mevBoostBlock != nil {
			return mevBoostBlock, nil
		}
	}
	payload, err := vs.getExecutionPayloadCapella(ctx, req.Slot, altairBlk.ProposerIndex, bytesutil.ToBytes32(altairBlk.ParentRoot))
	if err != nil {
		return nil, err
	}

	blk := &ethpb.BeaconBlockCapella{
		Slot:          altairBlk.Slot,
		ProposerIndex: altairBlk.ProposerIndex,
		ParentRoot:    altairBlk.ParentRoot,
		StateRoot:     params.BeaconConfig().ZeroHash[:],
		Body: &ethpb.BeaconBlockBodyCapella{
			RandaoReveal:      altairBlk.Body.RandaoReveal,
			Eth1Data:          altairBlk.Body.Eth1Data,
			Graffiti:          altairBlk.Body.Graffiti,
			ProposerSlashings: altairBlk.Body.ProposerSlashings,
			AttesterSlashings: altairBlk.Body.AttesterSlashings,
			Attestations:      altairBlk.Body.Attestations,
			Deposits:          altairBlk.Body.Deposits,
			VoluntaryExits:    altairBlk.Body.VoluntaryExits,
			SyncAggregate:     altairBlk.Body.SyncAggregate,
			ExecutionPayload:  payload,
		},
	}
	// Compute state root with the newly constructed block.
	wsb, err := consensusblocks.NewSignedBeaconBlock(
		&ethpb.SignedBeaconBlockCapella{Block: blk, Signature: make([]byte, 96)},
	)
	if err != nil {
		return nil, err
	}
	stateRoot, err := vs.computeStateRoot(ctx, wsb)
	if err != nil {
		interop.WriteBlockToDisk(wsb, true /*failed*/)
		return nil, fmt.Errorf("could not compute state root: %v", err)
	}
	blk.StateRoot = stateRoot
	return &ethpb.GenericBeaconBlock{Block: &ethpb.GenericBeaconBlock_Capella{Capella: blk}}, nil
}
