import 'dart:convert';
import 'dart:typed_data' as typed;
import 'dart:typed_data';

import 'package:hex/hex.dart';

import 'bech32.dart';

part 'nip19_keyset.dart';

enum Nip19KeyType { npub, nsec, note, nprofile, nevent, nrelay, unknown }

const int tlvTypeDefault = 0;
const int tlvTypeRelay = 1;

/// A Nostr event
class NostrEvent {
  final String id;
  final List<String> relays;

  NostrEvent(this.id, this.relays);
}

/// A Nostr profile
class NostrProfile {
  final String pubKey;
  final List<String> relays;

  NostrProfile(this.pubKey, this.relays);
}

final _b32 = Bech32();

/// Decodes a given bech32 string into its corresponding type
///
/// If you know what type of bech32 string you have, you can
/// pass it to one of the following functions:
/// - [decodePublicKey]
/// - [decode]
///
/// Returns one of: [Nip19KeySet], [NostrEvent] or [NostrProfile]
///
/// Throws [FormatException] if the bech32 string is invalid
dynamic decodeBech32(String data) {
  final Bech32DecodeResult res = _b32.decode(data);
  final Uint8List bits = _convertBits(res.words, 5, 8, false);
  final keyType = _parseNip19KeyType(res.hrp);

  if (keyType == Nip19KeyType.npub ||
      keyType == Nip19KeyType.nsec ||
      keyType == Nip19KeyType.note) {
    if (res.words.length < 32) {
      throw FormatException(
        'failed to decode public key bech32. Data is less than 32 bytes',
      );
    }

    return Nip19KeySet.from(HEX.encode(bits.sublist(0, 32)));
  }

  int i = 0;
  final List<String> relays = [];
  String? pubKey;

  while (i < bits.length) {
    final type = bits[i];
    final length = bits[i + 1];
    final value = bits.sublist(i + 2, i + 2 + length);

    if (type == tlvTypeDefault) {
      pubKey = HEX.encode(value);
    } else if (type == tlvTypeRelay) {
      relays.add(utf8.decode(value));
    }

    i += 2 + length;
  }

  if (pubKey == null) {
    throw FormatException(
      'failed to decode nprofile bech32. No public key found',
    );
  }

  if (keyType == Nip19KeyType.nprofile) {
    return NostrProfile(pubKey, relays);
  }

  if (keyType == Nip19KeyType.nevent) {
    return NostrEvent(pubKey, relays);
  }

  return Nip19KeySet();
}

/// Decodes a given bech32 string into its hex format
String decodePublicKey(String pubKey) {
  if (!pubKey.startsWith('npub1')) {
    throw ArgumentError('Invalid public key string');
  }

  final res = _b32.decode(pubKey);
  if (res.words.length < 32) {
    throw FormatException(
      'failed to decode public key bech32. Data is less than 32 bytes',
    );
  }

  final bits8 = _convertBits(res.words, 5, 8, false);

  return HEX.encode(bits8);
}

/// Decodes a given bech32 string into its hex format
String decodePrivateKey(String privKey) {
  if (!privKey.startsWith('nsec1')) {
    throw ArgumentError('Invalid private key string');
  }

  final res = _b32.decode(privKey);
  if (res.words.length < 32) {
    throw FormatException(
      'failed to decode public key bech32. Data is less than 32 bytes',
    );
  }

  final bits8 = _convertBits(res.words, 5, 8, false);

  return HEX.encode(bits8);
}

/// Encodes a given hex string into the bech32 public key format
String encodePublicKey(String publicKeyHex) =>
    _hexToBech32('npub', publicKeyHex);

/// Encodes a given hex string into the bech32 private key format
String encodePrivateKey(String publicKeyHex) =>
    _hexToBech32('nsec', publicKeyHex);

/// Encodes a given hex public key into the bech32 profile key format
String encodeNprofile(String hexKey, List<String> relays) =>
    _b32.encode('nprofile', _buildBuffer(HEX.decode(hexKey), relays));

/// Encodes a given event id into the bech32 event format
String encodeNevent(String hexKey, List<String> relays) =>
    _b32.encode('nevent', _buildBuffer(HEX.decode(hexKey), relays));

Uint8List _buildBuffer(List<int> b, List<String> relays) {
  var length = 2 + b.length;

  final utf8Relays = relays.map((e) {
    final l = utf8.encode(e);
    length += 2 + l.length;
    return l;
  }).toList(growable: false);

  ByteData data = ByteData(length);

  var current = 0;
  data.setUint8(0, tlvTypeDefault);
  data.setUint8(++current, b.length);

  for (var i = 0; i < b.length; i++) {
    data.setUint8(++current, b[i]);
  }

  for (var relay in utf8Relays) {
    data.setInt8(++current, tlvTypeRelay);
    data.setUint8(++current, relay.length);

    for (var i = 0; i < relay.length; i++) {
      data.setUint8(++current, relay[i]);
    }
  }

  return _convertBits(data.buffer.asUint8List(), 8, 5, true);
}

String _hexToBech32(String hrp, String hexKey) {
  var b = HEX.decode(hexKey);
  if (b.isEmpty) {
    throw FormatException('failed to decode public key hex');
  }

  var bits5 = _convertBits(b, 8, 5, true);

  return _b32.encode(hrp, bits5);
}

typed.Uint8List _convertBits(
    List<int> data, int fromBits, int toBits, bool pad) {
  if (fromBits < 1 || fromBits > 8 || toBits < 1 || toBits > 8) {
    throw FormatException('only bit groups between 1 and 8 allowed');
  }

  // The final bytes, each byte encoding toBits bits.
  var regrouped = <int>[];

  // Keep track of the next byte we create and how many bits we have
  // added to it out of the toBits goal.
  var nextByte = 0;
  var filledBits = 0;

  for (var b in data) {
    // Discard unused bits.
    b = b << (8 - fromBits);

    // How many bits remaining to extract from the input data.
    var remFromBits = fromBits;
    while (remFromBits > 0) {
      // How many bits remaining to be added to the next byte.
      var remToBits = toBits - filledBits;

      // The number of bytes to next extract is the minimum of
      // remFromBits and remToBits.
      var toExtract = remFromBits;
      if (remToBits < toExtract) {
        toExtract = remToBits;
      }

      // Add the next bits to nextByte, shifting the already
      // added bits to the left.
      nextByte = (nextByte << toExtract) | (b >> (8 - toExtract));

      // Discard the bits we just extracted and get ready for
      // next iteration and mask to a valid byte value.
      b = (b << toExtract) & 0xff;
      remFromBits -= toExtract;
      filledBits += toExtract;

      // If the nextByte is completely filled, we add it to
      // our regrouped bytes and start on the next byte.
      if (filledBits == toBits) {
        regrouped.add(nextByte);
        filledBits = 0;
        nextByte = 0;
      }
    }
  }

  // We pad any unfinished group if specified.
  if (pad && filledBits > 0) {
    nextByte = nextByte << (toBits - filledBits);
    regrouped.add(nextByte);
    filledBits = 0;
    nextByte = 0;
  }

  // Any incomplete group must be <= 4 bits, and all zeroes.
  if (filledBits > 0 && (filledBits > 4 || nextByte != 0)) {
    throw FormatException('invalid incomplete group');
  }

  return typed.Uint8List.fromList(regrouped);
}

Nip19KeyType _parseNip19KeyType(String hrp) {
  if (hrp.startsWith('npub')) {
    return Nip19KeyType.npub;
  } else if (hrp.startsWith('nsec')) {
    return Nip19KeyType.nsec;
  } else if (hrp.startsWith('note')) {
    return Nip19KeyType.note;
  } else if (hrp.startsWith('nprofile')) {
    return Nip19KeyType.nprofile;
  } else if (hrp.startsWith('nevent')) {
    return Nip19KeyType.nevent;
  } else if (hrp.startsWith('nrelay')) {
    return Nip19KeyType.nrelay;
  }

  return Nip19KeyType.unknown;
}
