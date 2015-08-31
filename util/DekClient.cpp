/*
 * DekClient.cpp
 *
 *  Created on: Aug 26, 2015
 *      Author: olic
 */


#include <unistd.h>

#include <ResponseCode.h>

#include "DekClient.h"

DekClient::DekClient(string sockPath)
:DaemonConnector(sockPath, SOCK_STREAM) {
}

EncKey *DekClient::encrypt(string alias, SymKey *key) {
	printf("DekClient::encrypt\n");

	int sock = doConnect();
	if(sock < 0) {
		printf("Cannot connect\n");
		return false;
	}

	shared_ptr<SerializedItem> sKey(key->serialize());
	sKey->dump("DekClient::encrypt");

	string cmd = "0 enc " + std::to_string(CommandCode::CommandEncrypt) + " "
			+ alias + " " + sKey->toString();
	printf("cmd :: %s\n", cmd.c_str());
	write(sock, cmd.c_str(), cmd.size() + 1);

	shared_ptr<DaemonEvent> event(monitor(sock));
	close(sock);

	if(event == NULL) {
		printf("Failed to encrypt : %d\n", __LINE__);
		return NULL;
	}

	event->dump("encrypt return event");

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
	printf("DekClient::decrypt\n");

	int sock = doConnect();
	if(sock < 0) {
		printf("Cannot connect\n");
		return false;
	}

	shared_ptr<SerializedItem> sKey(key->serialize());
	sKey->dump("DekClient::decrypt");

	string cmd = "0 enc " + std::to_string(CommandCode::CommandDecrypt) + " "
			+ alias + " " + sKey->toString();
	printf("cmd :: %s\n", cmd.c_str());
	write(sock, cmd.c_str(), cmd.size() + 1);

	shared_ptr<DaemonEvent> event(monitor(sock));
	close(sock);

	if(event == NULL) {
		printf("Failed to encrypt : %d\n", __LINE__);
		return NULL;
	}

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


DekControl::DekControl(string sockPath)
: DaemonConnector(sockPath, SOCK_STREAM) {
}

bool DekControl::create(string alias, Password *key) {
	printf("DekControl::create\n");

	int sock = doConnect();
	if(sock < 0) {
		printf("Cannot connect\n");
		return false;
	}

	shared_ptr<SerializedItem> sKey(key->serialize());
	sKey->dump("DekControl::create");

	string cmd = "0 ctl " + std::to_string(CommandCode::CommandCreateProfile) + " "
			+ alias + " " + sKey->toString();
	printf("cmd :: %s\n", cmd.c_str());
	write(sock, cmd.c_str(), cmd.size() + 1);

	shared_ptr<DaemonEvent> event(monitor(sock));
	close(sock);

	if(event->code == ResponseCode::CommandOkay) {
		return true;
	}

	printf("Failed to create [%d]\n", event->code);
	return false;
}

bool DekControl::remove(string alias) {
	printf("DekControl::remove\n");

	int sock = doConnect();
	if(sock < 0) {
		printf("Cannot connect\n");
		return false;
	}

	string cmd = "0 ctl " + std::to_string(CommandCode::CommandDeleteProfile) + " "
			+ alias;
	printf("cmd :: %s\n", cmd.c_str());
	write(sock, cmd.c_str(), cmd.size() + 1);

	shared_ptr<DaemonEvent> event(monitor(sock));
	close(sock);

	if(event->code == ResponseCode::CommandOkay) {
		return true;
	}

	printf("Failed to create [%d]\n", event->code);
	return false;
}

bool DekControl::unlock(string alias, Password *key) {
	printf("DekControl::unlock\n");

	shared_ptr<SerializedItem> sKey(key->serialize());

	sKey->dump("DekControl::unlock");

	int sock = doConnect();
	if(sock < 0) {
		printf("Cannot connect\n");
		return false;
	}

	string cmd = "0 ctl " + std::to_string(CommandCode::CommandUnlock) + " "
			+ alias + " " + sKey->toString();
	printf("cmd :: %s\n", cmd.c_str());
	write(sock, cmd.c_str(), cmd.size() + 1);

	shared_ptr<DaemonEvent> event(monitor(sock));
	close(sock);

	if(event->code == ResponseCode::CommandOkay) {
		return true;
	}

	printf("Failed to unlock [%d]\n", event->code);
	return false;
}

bool DekControl::lock(string alias) {
	printf("DekControl::lock\n");

	int sock = doConnect();
	if(sock < 0) {
		printf("Cannot connect\n");
		return false;
	}

	string cmd = "0 ctl " + std::to_string(CommandCode::CommandLock) + " "
			+ alias;
	printf("cmd :: %s\n", cmd.c_str());
	write(sock, cmd.c_str(), cmd.size() + 1);

	shared_ptr<DaemonEvent> event(monitor(sock));
	close(sock);

	if(event->code == ResponseCode::CommandOkay) {
		return true;
	}

	printf("Failed to create [%d]\n", event->code);
	return false;
}
