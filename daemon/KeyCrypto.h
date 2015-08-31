/*
 * KeyCrypto.h
 *
 *  Created on: Aug 17, 2015
 *      Author: olic
 */

#ifndef KEYCRYPTO_H_
#define KEYCRYPTO_H_

#include <map>

#include <Item.h>
#include <native_crypto.h>

using namespace std;

class KeyCrypto {
	class Action {
	public:
		Action() { }

		static int getCode(int state, int event) {
			return state | event;
		}
	};


	enum State {
		Uninitialized = 0x00000001,
		Locked = 0x00000002,
		Unlocked = 0x00000003
	};

public:
	enum Event {
		Boot = 0x00010000,
		Unlock = 0x00020000,
		Lock = 0x00030000,
		Create = 0x00040000,
		Remove = 0x00050000
	};

	KeyCrypto(string alias);
	virtual ~KeyCrypto();

	EncItem *encrypt(Item *item);
	Item *decrypt(EncItem *eitem);

	string getAlias() {
		return this->_alias;
	}

	void setPubKey(PubKey *pubKey) {
		this->_pubKey = pubKey;
	}
	PubKey *getPubKey() {
		return _pubKey;
	}

	void setPrivKey(PrivKey *privKey) {
		this->_privKey = privKey;
	}
	PrivKey *getPrivKey() {
		return _privKey;
	}
	void clrPrivKey() {
		if(this->_privKey != NULL)
			delete this->_privKey;

		this->_privKey = NULL;
	}

	void setSymKey(SymKey *symKey) {
		this->_symKey = symKey;
	}
	SymKey *getSymKey() {
		return _symKey;
	}
	void clrSymKey() {
		if(this->_symKey != NULL)
			delete this->_symKey;

		this->_symKey = NULL;
	}

	bool transit(Event event);

	bool isUnlocked() {
		if(_state == State::Unlocked)
			return true;
		return false;
	}

	void dump() {
		printf("KeyCrypto(%s)\n", _alias.c_str());

		if(_pubKey) _pubKey->dump(_alias.c_str());
		else printf("dump(%s) _pubKey empty\n", _alias.c_str());

		if(_privKey) _privKey->dump(_alias.c_str());
		else printf("dump(%s) _privKey empty\n", _alias.c_str());

		if(_symKey) _symKey->dump(_alias.c_str());
		else printf("dump(%s) _symKey empty\n", _alias.c_str());
	}
private:
	string _alias;

	PubKey *_pubKey;
	PrivKey *_privKey;
	SymKey *_symKey;

	KeyCrypto::State _state;
	KeyCrypto::State _oldState;
	std::map<int, KeyCrypto::State> StateDiagram;
};

class KeyCryptoManager {
public:
	static KeyCryptoManager *getInstance() {
		return _instance;
	}

	bool exists(string alias) {
		map<string, KeyCrypto *>::iterator it = mKeyCryptoMap.find(alias);
		if(it == mKeyCryptoMap.end())
			return false;
		else
			return true;
	}

	bool createKeyCrypto(string alias) {
		map<string, KeyCrypto *>::iterator it = mKeyCryptoMap.find(alias);
		if(it == mKeyCryptoMap.end()) {
			mKeyCryptoMap.insert(pair<string, KeyCrypto *> (alias, new KeyCrypto(alias)));
			return true;
		} else {
			printf("%s :: failed. already exists [%s]\n", __func__, alias.c_str());
			return false;
		}
	}

	KeyCrypto *getKeyCrypto(string alias) {
		KeyCrypto *kc = NULL;;
		map<string, KeyCrypto *>::iterator it = mKeyCryptoMap.find(alias);
		if(it == mKeyCryptoMap.end()) {
			printf("%s :: failed. not found [%s]\n", __func__, alias.c_str());
			return NULL;
		} else
			kc = it->second;

		return kc;
	}

	void clrKeyCrypto(string alias) {
		map<string, KeyCrypto *>::iterator it = mKeyCryptoMap.find(alias);
		if(it != mKeyCryptoMap.end()) {
			KeyCrypto *kc = it->second;
			delete kc;

			mKeyCryptoMap.erase(it);
		}
	}

private:
	map<string, KeyCrypto *> mKeyCryptoMap;

	KeyCryptoManager();
	static KeyCryptoManager *_instance;
};

#endif /* KEYCRYPTO_H_ */
