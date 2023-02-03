import 'package:nostr_client/src/nip19.dart' as nip19;
import 'package:test/test.dart';

const keyHex =
    '3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d';

const npub = 'npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6';

const nsec = 'nsec180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsgyumg0';

const relays = <String>["wss://r.x.com", "wss://djbas.sadkb.com"];

const encodedProfileBech32 =
    'nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p';

void main() {
  setUp(() async {});

  tearDown(() {});

  group('Nip19', () {
    group('should encode', () {
      test('a public key', () {
        final res = nip19.encodePublicKey(keyHex);
        expect(res, npub);
      });

      test('a private key', () {
        final res = nip19.encodePrivateKey(keyHex);
        expect(res, nsec);
      });

      test('a profile', () {
        final res = nip19.encodeNprofile(keyHex, relays);
        expect(res, encodedProfileBech32);
      });
    });

    group('should decode', () {
      test('a public key', () {
        final res = nip19.decodePublicKey(npub);
        expect(res, keyHex);
      });

      test('a private key', () {
        final res = nip19.decodePrivateKey(nsec);
        expect(res, keyHex);
      });

      test('a profile', () {
        final res = nip19.decodeBech32(encodedProfileBech32);
        expect(res, isA<nip19.NostrProfile>());
        expect(res.pubKey, keyHex);
        expect(res.relays, relays);
      });
    });
  });
}
