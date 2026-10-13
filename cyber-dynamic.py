#!/usr/bin/env python3

import hashlib
import json
import signal
import time
import zlib

from dataclasses import dataclass, asdict
from decimal import Decimal
from pathlib import Path


# ============================================================
# GODCHAIN + JOATT CONFIGURATION
# ============================================================

CHAIN_FILE = Path("godchain.json")
STATE_FILE = Path("godchain_joatt_state.json")

NETWORK = "GODCHAIN-TESTNET"
VERSION = "1.0-JOATT"

# GARBLE_SEED-derived proof-of-work target (256-bit integer).
GARBLE_SEED = (
    "510b80addb76ae1d02412d5ef4fe3fab"
    "5d87547b405bb90b381fbba2137fc553"
)
GARBLE_SEED_TARGET = int(GARBLE_SEED, 16)
INITIAL_TARGET = GARBLE_SEED_TARGET

# Dynamic target can move easier than the seed target, up to the
# largest 256-bit value, and harder down to a bounded minimum.
MAX_TARGET = (1 << 256) - 1
MIN_TARGET = max(1, INITIAL_TARGET >> 32)

TARGET_BLOCK_SECONDS = 10
RETARGET_CLAMP = 2  # each block changes target by at most x2
BLOCK_REWARD = 50
BLOCK_INTERVAL = TARGET_BLOCK_SECONDS

PBKDF2_ITERATIONS = 2048

RUNNING = True


# ============================================================
# BASIC CRYPTOGRAPHIC FUNCTIONS
# ============================================================

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(obj) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")


# ============================================================
# JOATT TEST DERIVATIVES
# ============================================================

def tiger128_test(data: bytes) -> bytes:
    """
    128-bit TEST-ONLY derivative.

    This is NOT the standardized Tiger hash.
    """

    return sha256(
        b"TIGER128|" +
        b"JOATT|" +
        b"TEST-ONLY|" +
        data
    )[:16]


def haval192_test(data: bytes) -> bytes:
    """
    192-bit TEST-ONLY derivative.

    This is NOT the standardized HAVAL algorithm.
    """

    return sha256(
        b"HAVAL192|" +
        b"JOATT|" +
        b"TEST-ONLY|" +
        data
    )[:24]


# ============================================================
# JOATT TRANSMOGRIFICATION
# ============================================================

def joatt(payload: bytes) -> dict:

    # --------------------------------------------------------
    # 1. Domain separation
    # --------------------------------------------------------

    normalized = (
        NETWORK.encode() +
        b"|" +
        b"JOATT-HAVAL192-TIGER128-TEST-ONLY|" +
        payload
    )

    # --------------------------------------------------------
    # 2. SHA-256 root
    # --------------------------------------------------------

    root = sha256(normalized)

    # --------------------------------------------------------
    # 3. PBKDF2-HMAC-SHA512
    # --------------------------------------------------------

    pbkdf = hashlib.pbkdf2_hmac(
        "sha512",
        root,
        b"JOATT-SALT-TEST-ONLY",
        PBKDF2_ITERATIONS,
        64
    )

    # --------------------------------------------------------
    # 4. Tiger128 test derivative
    # --------------------------------------------------------

    tiger128 = tiger128_test(
        pbkdf
    )

    # --------------------------------------------------------
    # 5. HAVAL192 test derivative
    # --------------------------------------------------------

    haval192 = haval192_test(
        tiger128 + pbkdf
    )

    # --------------------------------------------------------
    # 6. Adler-32 integrity value
    # --------------------------------------------------------

    adler32_value = zlib.adler32(
        haval192
    ) & 0xffffffff

    adler_bytes = adler32_value.to_bytes(
        4,
        "big"
    )

    # --------------------------------------------------------
    # 7. JOATT 64-bit identifier
    # --------------------------------------------------------

    identifier64 = sha256(
        b"JOATT-ID64|" +
        tiger128 +
        haval192 +
        adler_bytes
    )[:8]

    # --------------------------------------------------------
    # 8. Final JOATT 256-bit state
    # --------------------------------------------------------

    state256 = sha256(
        b"GODCHAIN-STATE256|" +
        root +
        pbkdf +
        tiger128 +
        haval192 +
        identifier64
    )

    return {

        "algorithm":
            "JOATT-TIGER128-HAVAL192-TEST",

        "network":
            NETWORK,

        "root_sha256":
            root.hex(),

        "pbkdf2_hmac_sha512":
            pbkdf.hex(),

        "tiger128_test":
            tiger128.hex(),

        "haval192_test":
            haval192.hex(),

        "adler32":
            f"{adler32_value:08x}",

        "identifier64":
            identifier64.hex(),

        "state256":
            state256.hex(),
    }


# ============================================================
# JOATT VALIDATION
# ============================================================

def validate_joatt(result: dict) -> bool:

    expected_lengths = {

        "root_sha256": 64,

        "pbkdf2_hmac_sha512": 128,

        "tiger128_test": 32,

        "haval192_test": 48,

        "adler32": 8,

        "identifier64": 16,

        "state256": 64,
    }

    for field, length in expected_lengths.items():

        if field not in result:
            return False

        if len(result[field]) != length:
            return False

        try:
            int(result[field], 16)

        except ValueError:
            return False

    return True


# ============================================================
# JOATT STATE PERSISTENCE
# ============================================================

def save_joatt_state(result: dict):

    data = {

        "name":
            "GODCHAIN",

        "network":
            NETWORK,

        "version":
            VERSION,

        "timestamp":
            time.time(),

        "result":
            result,
    }

    temporary = STATE_FILE.with_suffix(
        ".tmp"
    )

    temporary.write_text(
        json.dumps(
            data,
            indent=2
        )
    )

    temporary.replace(
        STATE_FILE
    )


# ============================================================
# BLOCK
# ============================================================

@dataclass
class Block:

    index: int

    timestamp: float

    previous_hash: str

    transactions: list

    nonce: int = 0

    hash: str = ""

    joatt_state: str = ""

    joatt_identifier: str = ""

    # Target used to mine this block; stored so historical PoW is verifiable.
    target: int = INITIAL_TARGET

    def header(self):

        return {

            "index":
                self.index,

            "timestamp":
                self.timestamp,

            "previous_hash":
                self.previous_hash,

            "transactions":
                self.transactions,

            "nonce":
                self.nonce,

            "joatt_state":
                self.joatt_state,

            "joatt_identifier":
                self.joatt_identifier,

            "target":
                f"{self.target:064x}",
        }

    def calculate_hash(self):

        return sha256_hex(
            canonical(
                self.header()
            )
        )

    def mine(self):

        while RUNNING:
            self.hash = self.calculate_hash()
            if int(self.hash, 16) <= self.target:
                return True
            self.nonce += 1

        return False


# ============================================================
# GODCHAIN
# ============================================================

class GodChain:

    def __init__(self):

        self.chain = []

        self.pending = []

        if CHAIN_FILE.exists():

            try:

                self.load()

                if self.validate():

                    print(
                        "[CHAIN] Existing chain loaded."
                    )

                else:

                    print(
                        "[CHAIN] Invalid chain."
                    )

                    self.chain.clear()

                    self.create_genesis()

            except Exception as error:

                print(
                    "[CHAIN] Load error:",
                    error
                )

                self.chain.clear()

                self.create_genesis()

        else:

            self.create_genesis()

    # ========================================================
    # GENESIS
    # ========================================================

    def create_genesis(self):

        payload = (
            b"GOD-GENOME|" +
            b"JOATT|" +
            b"GENESIS|" +
            b"1011"
        )

        joatt_result = joatt(
            payload
        )

        if not validate_joatt(
            joatt_result
        ):

            raise RuntimeError(
                "Genesis JOATT validation failed"
            )

        genesis = Block(

            index=0,

            timestamp=0,

            previous_hash="0" * 64,

            transactions=[

                {

                    "type":
                        "GENESIS",

                    "network":
                        NETWORK,

                    "message":
                        "GODCHAIN TESTNET",

                    "joatt":
                        joatt_result[
                            "state256"
                        ],
                }
            ],

            joatt_state=
                joatt_result[
                    "state256"
                ],

            joatt_identifier=
                joatt_result[
                    "identifier64"
                ]
        )

        genesis.hash = (
            genesis.calculate_hash()
        )

        self.chain = [
            genesis
        ]

        self.save()

        save_joatt_state(
            joatt_result
        )

    # ========================================================
    # LATEST BLOCK
    # ========================================================

    @property
    def latest(self):

        return self.chain[-1]

    def next_target(self):
        """Adjust target from the most recent block interval.

        Faster-than-target blocks make the target smaller (harder);
        slower blocks make it larger (easier). Adjustment is clamped
        to a factor of two per block and bounded by MIN/MAX_TARGET.
        """
        # Ignore the genesis timestamp (fixed at zero); wait until two
        # timestamped non-genesis blocks exist before retargeting.
        if len(self.chain) < 3:
            return INITIAL_TARGET

        previous = self.chain[-1]
        before = self.chain[-2]
        elapsed = max(1.0, previous.timestamp - before.timestamp)
        target = int(previous.target)

        # Inverse proportional adjustment, clamped to [0.5, 2.0].
        # Fast blocks => lower target/harder work; slow blocks => higher target.
        adjustment = Decimal(TARGET_BLOCK_SECONDS) / Decimal(str(elapsed))
        adjustment = max(
            Decimal(1) / Decimal(RETARGET_CLAMP),
            min(Decimal(RETARGET_CLAMP), adjustment)
        )
        target = int(Decimal(target) * adjustment)

        return max(MIN_TARGET, min(MAX_TARGET, target))

    # ========================================================
    # TRANSACTION
    # ========================================================

    def add_transaction(
        self,
        sender,
        recipient,
        amount
    ):

        if amount <= 0:

            raise ValueError(
                "Transaction amount must be positive"
            )

        transaction = {

            "sender":
                sender,

            "recipient":
                recipient,

            "amount":
                amount,

            "timestamp":
                time.time(),
        }

        self.pending.append(
            transaction
        )

        return transaction

    # ========================================================
    # AUTOMATIC BLOCK MINING
    # ========================================================

    def mine_block(self):

        transactions = list(
            self.pending
        )

        transactions.append({

            "type":
                "MINING_REWARD",

            "sender":
                NETWORK,

            "recipient":
                "GOD_MINER",

            "amount":
                BLOCK_REWARD,

            "timestamp":
                time.time(),
        })

        # ----------------------------------------------------
        # Serialize transaction state for JOATT
        # ----------------------------------------------------

        payload = canonical(
            transactions
        )

        # Add current chain state to JOATT domain.
        payload = (
            self.latest.hash.encode() +
            b"|" +
            payload
        )

        # ----------------------------------------------------
        # JOATT transformation
        # ----------------------------------------------------

        joatt_result = joatt(
            payload
        )

        if not validate_joatt(
            joatt_result
        ):

            raise RuntimeError(
                "JOATT validation failed"
            )

        save_joatt_state(
            joatt_result
        )

        # ----------------------------------------------------
        # Create block
        # ----------------------------------------------------

        block = Block(

            index=
                len(self.chain),

            timestamp=
                time.time(),

            previous_hash=
                self.latest.hash,

            transactions=
                transactions,

            joatt_state=
                joatt_result[
                    "state256"
                ],

            joatt_identifier=
                joatt_result[
                    "identifier64"
                ],

            target=self.next_target(),
        )

        print()
        print(f"[POW] target={block.target:064x}")
        print(
            f"[MINING] block={block.index}"
        )

        print(
            "[JOATT] "
            f"id64={block.joatt_identifier}"
        )

        print(
            "[JOATT] "
            f"state256={block.joatt_state}"
        )

        start = time.time()

        if not block.mine():

            return False

        elapsed = (
            time.time() - start
        )

        self.chain.append(
            block
        )

        self.pending.clear()

        print(
            f"[BLOCK] {block.index} "
            f"nonce={block.nonce} "
            f"time={elapsed:.3f}s"
        )

        print(
            f"[HASH] {block.hash}"
        )

        return True

    # ========================================================
    # CHAIN VALIDATION
    # ========================================================

    def validate(self):

        if not self.chain:

            return False

        # ----------------------------------------------------
        # Genesis
        # ----------------------------------------------------

        genesis = self.chain[0]

        if genesis.previous_hash != (
            "0" * 64
        ):

            return False

        if genesis.hash != (
            genesis.calculate_hash()
        ):

            return False

        # ----------------------------------------------------
        # Remaining blocks
        # ----------------------------------------------------

        for i in range(
            1,
            len(self.chain)
        ):

            current = self.chain[i]

            previous = self.chain[i - 1]

            # Hash integrity
            if current.hash != (
                current.calculate_hash()
            ):

                return False

            # Chain linkage
            if current.previous_hash != (
                previous.hash
            ):

                return False

            # Proof of work: block hash must satisfy its recorded target.
            try:
                target = int(current.target)
            except (TypeError, ValueError):
                return False

            if not (1 <= target <= MAX_TARGET):
                return False

            if int(current.hash, 16) > target:
                return False

            # JOATT state format
            if len(
                current.joatt_state
            ) != 64:

                return False

            if len(
                current.joatt_identifier
            ) != 16:

                return False

        return True

    # ========================================================
    # BALANCE
    # ========================================================

    def balance(
        self,
        address
    ):

        balance = 0

        for block in self.chain:

            for tx in block.transactions:

                if (
                    tx.get("sender")
                    == address
                ):

                    balance -= (
                        tx["amount"]
                    )

                if (
                    tx.get("recipient")
                    == address
                ):

                    balance += (
                        tx["amount"]
                    )

        return balance

    # ========================================================
    # SAVE CHAIN
    # ========================================================

    def save(self):

        data = {

            "name":
                "GODCHAIN",

            "network":
                NETWORK,

            "version":
                VERSION,

            "initial_target":
                f"{INITIAL_TARGET:064x}",

            "max_target":
                f"{MAX_TARGET:064x}",

            "min_target":
                f"{MIN_TARGET:064x}",

            "target_block_seconds":
                TARGET_BLOCK_SECONDS,

            "block_reward":
                BLOCK_REWARD,

            "chain": [

                asdict(block)

                for block
                in self.chain
            ],
        }

        temporary = (
            CHAIN_FILE.with_suffix(
                ".tmp"
            )
        )

        temporary.write_text(
            json.dumps(
                data,
                indent=2
            )
        )

        temporary.replace(
            CHAIN_FILE
        )

    # ========================================================
    # LOAD CHAIN
    # ========================================================

    def load(self):

        data = json.loads(
            CHAIN_FILE.read_text()
        )

        self.chain = [

            Block(
                **block
            )

            for block
            in data["chain"]
        ]


# ============================================================
# SIGNAL HANDLING
# ============================================================

def shutdown(
    signum,
    frame
):

    global RUNNING

    print(
        "\n[SHUTDOWN] Request received."
    )

    RUNNING = False


signal.signal(
    signal.SIGINT,
    shutdown
)

signal.signal(
    signal.SIGTERM,
    shutdown
)


# ============================================================
# AUTOMATION ENGINE
# ============================================================

def automate():

    chain = GodChain()

    print()
    print("=" * 64)
    print(
        "       GODCHAIN / JOATT AUTOMATION"
    )
    print("=" * 64)

    print(
        f"Network       : {NETWORK}"
    )

    print(
        f"Version       : {VERSION}"
    )

    print(
        f"Initial target: {INITIAL_TARGET:064x}"
    )

    print(
        f"Minimum target: {MIN_TARGET:064x}"
    )

    print(
        f"Maximum target: {MAX_TARGET:064x}"
    )

    print(
        f"Target time   : {TARGET_BLOCK_SECONDS}s"
    )

    print(
        f"Block reward  : {BLOCK_REWARD}"
    )

    print(
        f"Interval      : {BLOCK_INTERVAL}s"
    )

    print("=" * 64)

    while RUNNING:

        try:

            # ------------------------------------------------
            # 1. Validate existing chain
            # ------------------------------------------------

            if not chain.validate():

                raise RuntimeError(
                    "CHAIN VALIDATION FAILED"
                )

            print(
                f"[VALID] height="
                f"{len(chain.chain) - 1}"
            )

            # ------------------------------------------------
            # 2. Mine new block
            # ------------------------------------------------

            chain.mine_block()

            # ------------------------------------------------
            # 3. Validate resulting chain
            # ------------------------------------------------

            if not chain.validate():

                raise RuntimeError(
                    "POST-MINING VALIDATION FAILED"
                )

            print(
                "[VALID] post-mining"
            )

            # ------------------------------------------------
            # 4. Persist chain
            # ------------------------------------------------

            chain.save()

            print(
                f"[SAVE] {CHAIN_FILE}"
            )

            print(
                f"[SAVE] {STATE_FILE}"
            )

            # ------------------------------------------------
            # 5. Wait
            # ------------------------------------------------

            for _ in range(
                BLOCK_INTERVAL
            ):

                if not RUNNING:

                    break

                time.sleep(1)

        except Exception as error:

            print(
                f"[ERROR] {error}"
            )

            time.sleep(5)

    # ========================================================
    # CLEAN SHUTDOWN
    # ========================================================

    chain.save()

    print()
    print("=" * 64)
    print(
        "GODCHAIN STOPPED SAFELY"
    )

    print(
        f"Final height: "
        f"{len(chain.chain) - 1}"
    )

    print("=" * 64)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    automate()