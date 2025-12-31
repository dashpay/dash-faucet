#!/usr/bin/env python3
"""
Bundle evo-sdk and key generation utilities for browser use.

This script:
1. Copies @dashevo/evo-sdk/dist to static/dist
2. Rewrites WASM paths for browser compatibility
3. Bundles key generation utilities with esbuild
"""

import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = REPO_ROOT / 'static'
NODE_MODULES_DIR = REPO_ROOT / 'node_modules'


def copy_sdk_dist() -> bool:
    """Copy the evo-sdk dist directory to static/dist."""
    sdk_dist = NODE_MODULES_DIR / '@dashevo' / 'evo-sdk' / 'dist'
    dest = STATIC_DIR / 'dist'

    if not sdk_dist.exists():
        print(f"Error: SDK dist not found at {sdk_dist}")
        return False

    if dest.exists():
        shutil.rmtree(dest)

    shutil.copytree(sdk_dist, dest)
    print(f"Copied SDK dist to {dest}")
    return True


def rewrite_wasm_paths() -> None:
    """Replace bare module specifiers with relative paths for browser."""
    wasm_file = STATIC_DIR / 'dist' / 'wasm-sdk.module.js'
    if not wasm_file.exists():
        print(f"Warning: WASM file not found at {wasm_file}")
        return

    contents = wasm_file.read_text(encoding='utf-8')
    replacement = contents.replace(
        "@dashevo/wasm-sdk/compressed",
        "./sdk.compressed.js"
    )

    if replacement != contents:
        wasm_file.write_text(replacement, encoding='utf-8')
        print("Rewrote WASM module paths")
    else:
        print("WASM paths already correct")


def bundle_key_utils() -> bool:
    """Bundle key generation utilities with esbuild."""
    src_file = REPO_ROOT / 'scripts' / 'keys-src.js'
    out_file = STATIC_DIR / 'js' / 'keys.js'

    # Ensure output directory exists
    out_file.parent.mkdir(parents=True, exist_ok=True)

    # Create the source file for bundling
    src_content = '''
// Key generation utilities for browser
// This file is bundled by esbuild

import * as secp256k1 from '@noble/secp256k1';
import bs58check from 'bs58check';

// Generate a random private key (32 bytes)
function generatePrivateKey() {
    return secp256k1.utils.randomPrivateKey();
}

// Get compressed public key (33 bytes)
function getPublicKey(privateKey) {
    return secp256k1.getPublicKey(privateKey, true);
}

// Convert private key to WIF (testnet)
function toWIF(privateKey) {
    // Testnet prefix 0xef + private key + compression flag 0x01
    const extended = new Uint8Array(34);
    extended[0] = 0xef;
    extended.set(privateKey, 1);
    extended[33] = 0x01;
    return bs58check.encode(extended);
}

// Convert public key to base64
function toBase64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

// Convert bytes to hex
function toHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Generate all keys needed for identity creation
export function generateIdentityKeys() {
    // Asset lock key (one-time)
    const assetLockPrivate = generatePrivateKey();
    const assetLockPublic = getPublicKey(assetLockPrivate);

    // 4 Identity keys with WASM SDK expected format
    // keyType: ECDSA_SECP256K1, BLS12_381, ECDSA_HASH160, BIP13_SCRIPT_HASH
    // purpose: AUTHENTICATION, ENCRYPTION, DECRYPTION, TRANSFER, WITHDRAW, VOTING, OWNER
    // securityLevel: MASTER, CRITICAL, HIGH, MEDIUM
    const keySpecs = [
        { id: 0, purpose: 'AUTHENTICATION', securityLevel: 'MASTER', name: 'Master (Authentication)' },
        { id: 1, purpose: 'AUTHENTICATION', securityLevel: 'HIGH', name: 'High Auth' },
        { id: 2, purpose: 'AUTHENTICATION', securityLevel: 'CRITICAL', name: 'Critical Auth' },
        { id: 3, purpose: 'TRANSFER', securityLevel: 'CRITICAL', name: 'Transfer' },
    ];

    const identityKeys = keySpecs.map(spec => {
        const priv = generatePrivateKey();
        const pub = getPublicKey(priv);
        return {
            id: spec.id,
            keyType: 'ECDSA_SECP256K1',
            purpose: spec.purpose,
            securityLevel: spec.securityLevel,
            data: toBase64(pub),
            readOnly: false,
            privateKeyHex: toHex(priv),
            privateKeyWif: toWIF(priv), // Keep WIF for user display
            _name: spec.name
        };
    });

    return {
        assetLock: {
            privateKeyHex: toHex(assetLockPrivate),
            privateKeyWif: toWIF(assetLockPrivate),
            publicKeyBase64: toBase64(assetLockPublic),
            publicKeyHex: toHex(assetLockPublic)
        },
        identityKeys
    };
}

// Export to window for non-module usage
if (typeof window !== 'undefined') {
    window.generateIdentityKeys = generateIdentityKeys;
}
'''
    src_file.write_text(src_content, encoding='utf-8')

    # Run esbuild to bundle
    try:
        result = subprocess.run(
            [
                'npx', 'esbuild',
                str(src_file),
                '--bundle',
                '--format=esm',
                '--target=es2020',
                f'--outfile={out_file}',
                '--minify'
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print(f"esbuild error: {result.stderr}")
            return False

        print(f"Bundled key utilities to {out_file}")

        # Clean up source file
        src_file.unlink()
        return True

    except FileNotFoundError:
        print("Error: esbuild not found. Run 'npm install' first.")
        return False


def main():
    """Main entry point."""
    print("Bundling SDK and utilities for browser...")

    if not copy_sdk_dist():
        return 1

    rewrite_wasm_paths()

    if not bundle_key_utils():
        return 1

    print("Done!")
    return 0


if __name__ == '__main__':
    exit(main())
