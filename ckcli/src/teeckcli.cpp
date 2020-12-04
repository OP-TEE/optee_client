// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Vaisala Oyj.
 */

#ifndef DEBUG
#define DEBUG 0
#endif

#include "TeeCkCliConstants.hpp"

#include <ckteeaclc.h>
#include <ckteecpp/cktee.hpp>
#include <ckteec_extensions.h>

#include <docopt/docopt.h>
#include <uuid/uuid.h>

#include <cstring>
#include <iostream>
#include <map>

using std::cerr;
using std::cin;
using std::cout;
using std::endl;
using std::map;
using std::string;

static const char USAGE[] =
R"(OP-TEE PKCS#11 Trusted Application Command Line Interface

Usage:
  teeckcli --slot=SLOTNUM init --label=LABEL --set-so-pin=NEW-PIN
  teeckcli --slot=SLOTNUM init --label=LABEL --set-so-group=NEW-GROUP
  teeckcli --slot=SLOTNUM --so-pin=CUR-PIN user-login --set-user-pin=NEW-PIN
  teeckcli --slot=SLOTNUM --so-group=CUR-GROUP user-login --set-user-group=NEW-GROUP
  teeckcli (-h | --help)
  teeckcli --version

Options:
  --slot=SLOTNUM              Number of the slot to use (SLOT_ID)
  --label=LABEL               Label (string) for the token
  --set-so-pin=NEW-PIN        New PIN for the Security Officer (SO)
  --set-so-group=NEW-GROUP    New group name for the Security Officer (SO)
  --so-pin=CUR-PIN            Current PIN of the Security Officer (SO)
  --so-group=CUR-GROUP        Current group name of the Security Officer (SO)
  --set-user-pin=NEW-PIN      New PIN for the User
  --set-user-group=NEW-GROUP  New group name for the User
  -h --help                   Show this screen.
  --version                   Show version.

Commands:
  init                        Initialize token and set Security Officer (SO) login
  user-login                  Set User login (PIN or group, must match SO login type)
)";
/*
 * If SO and user login become independent
 *   teeckcli --slot=SLOTNUM (--so-pin=SO-PIN|--so-group=SO-GROUP) user-login --set-user-pin=USER-PIN
 *   teeckcli --slot=SLOTNUM (--so-pin=SO-PIN|--so-group=SO-GROUP) user-login --set-user-group=USER-GROUPNAME
 */

namespace {

constexpr CK_ULONG LABEL_SIZE = 32;

void printArgs(const map<string, docopt::value> &args) {
#if DEBUG
	for (auto const& arg : args)
	{
		cout << arg.first << " " << arg.second << endl;
	}
#else
	(void)args;
#endif
}

CK_RV initTokenWithPin(string tokenLabel, CK_SLOT_ID slotId, string soPin) {
	cktee::DefaultCryptoki cryptoki;
	// TODO: C_InitToken does not declare const. In principle we should pass copies
	CK_UTF8CHAR_PTR pSoPin = (CK_UTF8CHAR_PTR) soPin.c_str();
	CK_ULONG pin_len = soPin.size();
	CK_UTF8CHAR label[LABEL_SIZE];

	memset(label, ' ', sizeof(label));
	memcpy(label, tokenLabel.c_str(), tokenLabel.size());
	auto pLabel = reinterpret_cast<CK_UTF8CHAR_PTR>(&label);
	CK_RV rv = C_InitToken(slotId, pSoPin, pin_len, pLabel);

	return rv;
}

CK_RV initTokenWithGroup(string tokenLabel, CK_SLOT_ID slotId, gid_t soGroup) {
	enum rv_groupmember checkMember = ckteeaclc_current_user_is_member_of(soGroup);

	switch (checkMember) {
		case NOT_MEMBER:
			throw std::runtime_error("Current user is not member of requested group");
			break;
		case IS_MEMBER:
			break;
		default:
			throw std::runtime_error("Error when trying to check group membership");
			break;
	}
	ckteec_invoke_init_login_group(soGroup);

	CK_UTF8CHAR_PTR pSoPin = (CK_UTF8CHAR_PTR) "";
	CK_ULONG pin_len = 0;
	CK_UTF8CHAR label[LABEL_SIZE];

	memset(label, ' ', sizeof(label));
	memcpy(label, tokenLabel.c_str(), tokenLabel.size());
	auto pLabel = reinterpret_cast<CK_UTF8CHAR_PTR>(&label);
	CK_RV rv = C_InitToken(slotId, pSoPin, pin_len, pLabel);

	return rv;
}

CK_RV doInitPin(const cktee::PKCS11Session &p11Session, const cktee::PKCS11Login& /*&p11Login*/, const string &userPin) {
	const CK_SESSION_HANDLE sessionHandle = p11Session.getHandle();
	CK_UTF8CHAR_PTR pin = (CK_UTF8CHAR_PTR) userPin.c_str();
	CK_ULONG pin_len = userPin.size();
	CK_RV rv = C_InitPIN(sessionHandle, pin, pin_len);

	if (rv != CKR_OK)
		cerr << "Failed to set user PIN" << endl;
	return rv;
}

/**
 * Set user login pin to <tt>userPin</tt> in slot <tt>slotId</tt>.
 * @param slotId slot number
 * @param userPin user PIN string
 * @param soPin SO PIN
 * @return a CK_RV compliant return value
 */
CK_RV setUserLoginPin(CK_SLOT_ID slotId, const string &userPin, const string &soPin) {
	cktee::DefaultCryptoki cryptoki;
	cktee::DefaultPKCS11Session p11Session = cryptoki.openSession(slotId);
	cktee::DefaultPKCS11Login p11Login(p11Session, CKU_SO, soPin);

	return doInitPin(p11Session, p11Login, userPin);
}

/**
 * Set token user login group to <tt>userGid</tt> in slot <tt>slotId</tt>.
 * @param slotId slot number
 * @param userGid user login group id
 * @param soGroup SO group to login with.
 * @return a CK_RV compliant return value
 */
CK_RV setUserLoginGroup(CK_SLOT_ID slotId, gid_t userGid, gid_t soGroup) {
	enum rv_groupmember checkMember = ckteeaclc_current_user_is_member_of(soGroup);

	switch (checkMember) {
		case NOT_MEMBER:
			throw std::runtime_error("Current user is not member of requested group");
			break;
		case IS_MEMBER:
			break;
		default:
			throw std::runtime_error("Error when trying to check group membership");
			break;
	}
	cktee::GroupLoginCryptoki cryptoki{soGroup};
	cktee::GroupLoginPKCS11Session p11Session = cryptoki.openSession(slotId);
	cktee::GroupPKCS11Login p11Login{p11Session, CKU_SO};
	char uuid_buf[CKTEEACLC_L_UUID];

	if (ckteeaclc_group_acl_uuid(uuid_buf, userGid))
		throw std::runtime_error("Encoding uuid failed");
	string uuidBuf{uuid_buf};

	return doInitPin(p11Session, p11Login, uuidBuf);
}

} // anonymous namespace

int main(int argc, char* argv[]) {
	ckteeaclc_lib_init();

	map<string, docopt::value> args = docopt::docopt(
		USAGE,
		{argv + 1, argv + argc},
		true, // show help if requested
		"teeckcli "+ tee::ckcli::TEECKCLI_VERSION); // version string

	printArgs(args);

	CK_SLOT_ID slotId = args["--slot"].asLong();

	if (args["init"].asBool()) {
		string tokenLabel = args["--label"].asString();
		if (bool(args["--set-so-pin"])) {
			string soPin = args["--set-so-pin"].asString();
			return initTokenWithPin(tokenLabel, slotId, soPin);
		} else {
			string soGroup = args["--set-so-group"].asString();
			gid_t soGid = 0;
			int err = ckteeaclc_try_resolve_group(&soGid, soGroup.c_str());

			if (soGid== CKTEEACLC_NO_GROUP) {
				cerr << "Did not resolve SO group id for " << soGroup << endl;
				cerr << "Return code was "  << err << endl;
				return err;
			}
			return initTokenWithGroup(tokenLabel, slotId, soGid);
		}
	} else if (args["user-login"].asBool()) {
		if (bool(args["--set-user-pin"])) {
			string userPin = args["--set-user-pin"].asString();
			string soPin = args["--so-pin"].asString();

			return setUserLoginPin(slotId, userPin, soPin);
		} else {
			string userGroupName = args["--set-user-group"].asString();
			gid_t userGid = 0;
			int err = ckteeaclc_try_resolve_group(&userGid, userGroupName.c_str());

			if (userGid == CKTEEACLC_NO_GROUP) {
				cerr << "Did not resolve group id for " << userGroupName << endl;
				cerr << "Return code was "  << err << endl;
				return err;
			}
			string soGroupName = args["--so-group"].asString();
			gid_t soGid = 0;
			err = ckteeaclc_try_resolve_group(&soGid, soGroupName.c_str());

			if (soGid== CKTEEACLC_NO_GROUP) {
				cerr << "Did not resolve SO group id for " << soGroupName << endl;
				cerr << "Return code was "  << err << endl;
				return err;
			}
			return setUserLoginGroup(slotId, userGid, soGid);
		}
	}
	// should never reach
	cerr << "Implementation missing for arguments" << endl;
	return 1;
}
