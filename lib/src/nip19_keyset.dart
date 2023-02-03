part of 'nip19.dart';

/// A set of NIP19 keys
///
/// https://github.com/nostr-protocol/nips/blob/master/19.md
class Nip19KeySet {
  final List<String> relays;

  late final String hex;
  late final String bech32;

  Nip19KeySet({
    this.relays = const [],
    this.hex = '',
    this.bech32 = '',
  });

  /// Generate a Nip19KeySet from a public key hex string
  /// or a public key bech32 string
  Nip19KeySet.from(String key, {this.relays = const []}) {
    if (key.startsWith('npub1')) {
      bech32 = key;
      hex = decodePublicKey(key);

      return;
    }

    hex = key;
    bech32 = encodePublicKey(key);
  }

  copyWith({
    List<String>? relays,
    Nip19KeyType? type,
    String? hex,
    String? bech32,
  }) {
    return Nip19KeySet(
      relays: relays ?? this.relays,
      hex: hex ?? this.hex,
      bech32: bech32 ?? this.bech32,
    );
  }

  @override
  String toString() =>
      'Nip19{pubKeyHex: $hex, pubKeyBech32: $bech32, relays: $relays}';

  Map<String, dynamic> toJson() {
    return {
      'pubKeyHex': hex,
      'pubKeyBech32': bech32,
      'relays': relays,
    };
  }
}
