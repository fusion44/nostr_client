import 'dart:convert';

import 'package:http/http.dart' as http;

import 'package:nostr_client/nostr_client.dart';

void main() async {
  // Create a new relay instance and connect to the relay
  final relay = Relay('wss://relay.nostr.info');
  relay.connect();

  final nip05Service = NIP05Service(http.Client());

  // Print events sent by the relay
  relay.stream.whereIsEvent().listen(((event) async {
    if (event.kind == EventKind.metadata) {
      final data = jsonDecode(event.content);
      if (!data.containsKey('nip05')) return;
      final m = await nip05Service.get(event.pubkey, data['nip05']);

      return print(m);
    }

    print(event);
  }));

  // Request text events from the relay and subscribe to updates
  final filter = Filter(
    kinds: [EventKind.text],
    limit: 10,
  );
  final subscriptionId = relay.subscribe(filter);

  final metadataFilter = Filter(
    authors: [
      '82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2', // @jack
    ],
    kinds: [EventKind.metadata, EventKind.recommendRelay],
  );
  final metaSubscriptionId = relay.subscribe(metadataFilter);

  // wait 5 seconds for the data to arrive
  await Future.delayed(Duration(seconds: 5));

  // Cancel the subscription
  relay.unsubscribe(subscriptionId);
  relay.unsubscribe(metaSubscriptionId);

  // Disconnect from the relay
  relay.disconnect();
}
