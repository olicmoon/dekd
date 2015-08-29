/*
 * DekClient.cpp
 *
 *  Created on: Aug 26, 2015
 *      Author: olic
 */


#include <unistd.h>

#include "DekClient.h"
#include "DaemonConnector.h"
#include <ResponseCode.h>

DekClient::DekClient(string sockPath) {
	_sockPath = sockPath;
}

int DekClient::connect() {
	return socket_local_client(_sockPath.c_str(), SOCK_STREAM);
}

string DekClient::monitor(int sock) {
	char *buffer = (char *)malloc(4096);

	while(1) {
		fd_set read_fds;
		struct timeval to;
		int rc = 0;

		to.tv_sec = 10;
		to.tv_usec = 0;

		FD_ZERO(&read_fds);
		FD_SET(sock, &read_fds);

		if ((rc = select(sock +1, &read_fds, NULL, NULL, &to)) < 0) {
			fprintf(stderr, "Error in select (%s)\n", strerror(errno));
			free(buffer);
			return NULL;
		} else if (!rc) {
			continue;
			fprintf(stderr, "[TIMEOUT]\n");
			return NULL;
		} else if (FD_ISSET(sock, &read_fds)) {
			memset(buffer, 0, 4096);
			if ((rc = read(sock, buffer, 4096)) <= 0) {
				if (rc == 0)
					fprintf(stderr, "Lost connection - did it crash?\n");
				else
					fprintf(stderr, "Error reading data (%s)\n", strerror(errno));
				free(buffer);

				return NULL;
			}

			int offset = 0;
			int i = 0;

			for (i = 0; i < rc; i++) {
				if (buffer[i] == '\0') {
					int code;
					char tmp[4];

					strncpy(tmp, buffer + offset, 3);
					tmp[3] = '\0';
					code = atoi(tmp);

					string resp = buffer + offset;
					printf("%s\n", resp.c_str());

					if (code >= 200 && code < 600) {
						free(buffer);
						return resp;
					}

					offset = i + 1;
				}
			}
		}
	}
	free(buffer);
	return NULL;
}

EncKey *DekClient::encrypt(string alias, SymKey *key) {
	shared_ptr<SerializedItem> sKey(key->serialize());

	sKey->dump("DekClient::encrypt");

	int sock = connect();
	string cmd = "0 enc " + std::to_string(CommandCode::CommandEncrypt) + " "
			+ alias + " " + sKey->toString();
	printf("cmd :: %s\n", cmd.c_str());
	write(sock, cmd.c_str(), cmd.size() + 1);

	string resp = monitor(sock);

	printf("resp :: %s\n", resp.c_str());
	shared_ptr<DaemonEvent> event(DaemonEvent::parseRawEvent(resp));
	event->dump("test");

	if(event->code == ResponseCode::CommandOkay) {
		int alg = std::stoi(event->message[0]);
		shared_ptr<SerializedItem> sItem;
		switch(alg) {
		case CryptAlg::AES:
			sItem = shared_ptr<SerializedItem> (
					new SerializedItem(alg, event->message[1].c_str(),
							event->message[2].c_str(), "?"));
			break;
		case CryptAlg::ECDH:
			sItem = shared_ptr<SerializedItem> (
					new SerializedItem(alg, event->message[1].c_str(),
							event->message[2].c_str(), event->message[3].c_str()));
			break;
		default:
			printf("Failed to encrypt. unknown alg %d\n", alg);
			break;
		}

		return (EncKey *) sItem->deserialize();
	} else {
		printf("Failed to encrypt [%d]\n",
				(event == NULL) ? ResponseCode::CommandFailed : event->code);
		return NULL;
	}

	return NULL;
}

SymKey *DekClient::decrypt(string alias, EncKey *key) {
	shared_ptr<SerializedItem> sKey(key->serialize());

	sKey->dump("DekClient::decrypt");

	int sock = connect();
	string cmd = "0 enc " + std::to_string(CommandCode::CommandDecrypt) + " "
			+ alias + " " + sKey->toString();
	printf("cmd :: %s\n", cmd.c_str());
	write(sock, cmd.c_str(), cmd.size() + 1);

	string resp = monitor(sock);

	printf("resp :: %s\n", resp.c_str());
	shared_ptr<DaemonEvent> event(DaemonEvent::parseRawEvent(resp));
	event->dump("decrypt");

	if(event->code == ResponseCode::CommandOkay) {
		int alg = std::stoi(event->message[0]);
		if(alg != CryptAlg::PLAIN) {
			printf("Failed to decrypt : result is not plain text\n");
			return NULL;
		}
		shared_ptr<SerializedItem> sItem(
					new SerializedItem(CryptAlg::PLAIN, event->message[1].c_str(),
							"?", "?"));
		return (SymKey *) sItem->deserialize();
	} else {
		printf("Failed to decrypt [%d]\n",
				(event == NULL) ? ResponseCode::CommandFailed : event->code);
		return NULL;
	}

	return NULL;
}
