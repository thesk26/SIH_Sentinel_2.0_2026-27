import crypto from 'crypto';
import { db } from '../database/schema.js';

export interface BlockchainBlock {
  block_index: number;
  timestamp: number;
  evidence_hash: string;
  device_id: string;
  incident_id?: string;
  previous_block_hash: string;
  merkle_root: string;
  signature: string;
  canonical_data: string;
}

export class BlockchainEvidenceService {
  private static GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

  public static recordEvidence(
    deviceId: string,
    evidencePayload: object,
    incidentId?: string
  ): { txId: string; evidenceHash: string; blockIndex: number; isValid: boolean } {
    // 1. Canonical JSON serialization (keys sorted)
    const canonicalStr = JSON.stringify(evidencePayload, Object.keys(evidencePayload).sort());
    const evidenceHash = crypto.createHash('sha256').update(canonicalStr).digest('hex');

    // 2. Fetch latest block to maintain cryptographic chain
    const lastBlock = db.prepare('SELECT block_index, evidence_hash FROM blockchain_records ORDER BY block_index DESC LIMIT 1').get() as { block_index: number; evidence_hash: string } | undefined;
    const blockIndex = lastBlock ? lastBlock.block_index + 1 : 0;
    const previousBlockHash = lastBlock ? lastBlock.evidence_hash : this.GENESIS_HASH;

    // 3. Merkle root & signature calculation
    const merkleRoot = crypto.createHash('sha256').update(previousBlockHash + evidenceHash).digest('hex');
    const signature = crypto.createHmac('sha256', 'SENTINEL_SYSTEM_KEY').update(merkleRoot + blockIndex).digest('hex');
    const txId = '0x' + crypto.createHash('sha256').update(signature + Date.now()).digest('hex');

    const timestamp = Date.now();

    db.prepare(`
      INSERT INTO blockchain_records (tx_id, evidence_hash, device_id, incident_id, timestamp, block_index, previous_block_hash, merkle_root, signature, canonical_data)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(txId, evidenceHash, deviceId, incidentId || null, timestamp, blockIndex, previousBlockHash, merkleRoot, signature, canonicalStr);

    return {
      txId,
      evidenceHash,
      blockIndex,
      isValid: true
    };
  }

  public static verifyEvidence(txId: string): {
    status: 'VALID' | 'TAMPERED' | 'NOT_FOUND';
    details: string;
    record?: BlockchainBlock;
  } {
    const record = db.prepare('SELECT * FROM blockchain_records WHERE tx_id = ?').get(txId) as BlockchainBlock | undefined;
    if (!record) {
      return { status: 'NOT_FOUND', details: 'Transaction ID not registered in blockchain ledger.' };
    }

    // Recalculate hash of stored canonical data
    const recalculatedEvidenceHash = crypto.createHash('sha256').update(record.canonical_data).digest('hex');
    if (recalculatedEvidenceHash !== record.evidence_hash) {
      return {
        status: 'TAMPERED',
        details: `Cryptographic mismatch: computed hash (${recalculatedEvidenceHash}) does not match registered block evidence hash (${record.evidence_hash}). Evidence has been altered!`,
        record
      };
    }

    // Verify Merkle integrity with previous block
    const expectedMerkle = crypto.createHash('sha256').update(record.previous_block_hash + record.evidence_hash).digest('hex');
    if (expectedMerkle !== record.merkle_root) {
      return {
        status: 'TAMPERED',
        details: 'Merkle root verification failed against chain predecessor.',
        record
      };
    }

    return {
      status: 'VALID',
      details: 'Cryptographic proof intact. SHA-256 evidence matches immutable block ledger.',
      record
    };
  }

  public static getAllRecords(limit = 50) {
    return db.prepare('SELECT * FROM blockchain_records ORDER BY block_index DESC LIMIT ?').all(limit);
  }
}
