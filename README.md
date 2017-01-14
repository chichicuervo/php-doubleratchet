# php-doubleratchet

An implementation of [Open Whisper System](https://whispersystemsorg)'s [Double Ratchet Algorithm](https://whispersystems.org/docs/specifications/doubleratchet/) in PHP (and libsodium).

## Usage

#### Alice:

```php
<?php

require_once '../vendor/autoload.php'; // yes, this uses Composer

use jbelich\DoubleRatchet\Protocol as DoubleRatchet;
use jbelich\DoubleRatchet\Crypt;

$bobs_pubkey = $GET_FROM_INITIAL_HANDSHAKE;
$alice_keypair = $YOU_PREMADE_THIS;

$alice = new DoubleRatchet(DoubleRatchet::MODE_SENDER, [
    'local_key_pair' => $alice_keypair,
    'remote_public_key' => $bobs_pubkey
]);

$to_bob = $alice->encrypt('Alice -> Bob #1.0'); // returns [$headertext, $ciphertext]

// save state for future use
$alice_sleep = $alice->getStateArray();
unset($alice);

send_to_bob($to_bob[0], $to_bob[1]);

?>
```

#### Bob:

```php
<?php

require_once '../vendor/autoload.php';

use jbelich\DoubleRatchet\Protocol as DoubleRatchet;
use jbelich\DoubleRatchet\Crypt;

$alices_pubkey = $GET_FROM_INITIAL_HANDSHAKE;
$bob_keypair = $YOU_PREMADE_THIS;

$bob = new DoubleRatchet(DoubleRatchet::MODE_RECEIVER, [
    'local_key_pair' => $bob_keypair,
    'remote_public_key' => $alices_pubkey
]);

$to_bob = $PARSED_FROM_ALICE;

$from_alice = $bob->Decrypt($to_bob[0], $to_bob[1]);

echo $from_alice; // "Alice -> Bob #1.0"

// save conversation state
$bob_sleep = $bob->getStateArray();
unset($bob);

```

### TODOs


- [Encrypted headers](https://whispersystems.org/docs/specifications/doubleratchet/#double-ratchet-with-header-encryption).
- [X3DH](https://whispersystems.org/docs/specifications/x3dh/) enhanced Diffie-Hellman
- Abstract away "skipped" message key array, to better support offline storage
- implement Sodium's recommended Blake2 KDF hash function
- derive AEAD nonce according to options from spec
- generate 80 byte HKDF as per spec
