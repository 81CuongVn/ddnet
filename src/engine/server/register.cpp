#include "register.h"

#include <base/log.h>
#include <engine/console.h>
#include <engine/engine.h>
#include <engine/shared/config.h>
#include <engine/shared/http.h>
#include <engine/shared/json.h>
#include <engine/shared/masterserver.h>
#include <engine/shared/network.h>
#include <engine/shared/uuid_manager.h>

class CRegister : public IRegister
{
	enum
	{
		STATUS_NONE = 0,
		STATUS_OK,
		STATUS_NEEDCHALLENGE,
		STATUS_NEEDINFO,

		PROTOCOL_TW6_IPV6 = 0,
		PROTOCOL_TW6_IPV4,
		PROTOCOL_TW7_IPV6,
		PROTOCOL_TW7_IPV4,
		NUM_PROTOCOLS,
	};

	static bool StatusFromString(int *pResult, const char *pString);
	static bool ProtocolFromUrl(int *pResult, const char *pUrl);
	static const char *ProtocolToScheme(int Protocol);
	static const char *ProtocolToString(int Protocol);
	static bool ProtocolFromString(int *pResult, const char *pString);
	static const char *ProtocolToSystem(int Protocol);
	static IPRESOLVE ProtocolToIpresolve(int Protocol);

	static void ConchainOnConfigChange(IConsole::IResult *pResult, void *pUserData, IConsole::FCommandCallback pfnCallback, void *pCallbackUserData);

	class CGlobal
	{
	public:
		~CGlobal()
		{
			lock_destroy(m_Lock);
		}

		LOCK m_Lock = lock_create();
		int m_InfoSerial GUARDED_BY(m_Lock) = -1;
		int m_LatestSuccessfulInfoSerial GUARDED_BY(m_Lock) = -1;
	};

	class CProtocol
	{
		class CShared
		{
		public:
			CShared(std::shared_ptr<CGlobal> pGlobal) :
				m_pGlobal(std::move(pGlobal))
			{
			}
			~CShared()
			{
				lock_destroy(m_Lock);
			}

			std::shared_ptr<CGlobal> m_pGlobal;
			LOCK m_Lock = lock_create();
			bool m_Registered GUARDED_BY(m_Lock) = false;
			int m_LatestResponseStatus GUARDED_BY(m_Lock) = STATUS_NONE;
			int m_LatestResponseIndex GUARDED_BY(m_Lock) = -1;
		};

		class CJob : public IJob
		{
			int m_Protocol;
			int m_Index;
			int m_InfoSerial;
			std::shared_ptr<CShared> m_pShared;
			std::unique_ptr<CHttpRequest> m_pRegister;
			virtual void Run();

		public:
			CJob(int Protocol, int Index, int InfoSerial, std::shared_ptr<CShared> pShared, std::unique_ptr<CHttpRequest> &&pRegister) :
				m_Protocol(Protocol),
				m_Index(Index),
				m_InfoSerial(InfoSerial),
				m_pShared(std::move(pShared)),
				m_pRegister(std::move(pRegister))
			{
			}
			virtual ~CJob() = default;
		};

		CRegister *m_pParent;
		int m_Protocol;

		std::shared_ptr<CShared> m_pShared;
		int m_NumTotalRequests = 0;
		bool m_NewChallengeToken = false;
		bool m_HaveChallengeToken = false;
		char m_aChallengeToken[128] = {0};

		void CheckChallengeStatus();

	public:
		int64_t m_PrevRegister = -1;
		int64_t m_NextRegister = -1;

		CProtocol(CRegister *pParent, int Protocol);
		void OnToken(const char *pToken);
		void SendRegister();
		void Update();
	};

	CConfig *m_pConfig;
	IConsole *m_pConsole;
	IEngine *m_pEngine;
	int m_ServerPort;
	char m_aConnlessRequestTokenHex[16];

	std::shared_ptr<CGlobal> m_pGlobal = std::make_shared<CGlobal>();
	bool m_aProtocolEnabled[NUM_PROTOCOLS] = {true, true, true, true};
	CProtocol m_aProtocols[NUM_PROTOCOLS];

	char m_aRegisterExtra[256];

	char m_aVerifyPacket[sizeof(SERVERBROWSE_CHALLENGE) + UUID_MAXSTRSIZE];
	CUuid m_Secret = RandomUuid();
	bool m_GotServerInfo = false;
	char m_aServerInfo[16384];

public:
	CRegister(CConfig *pConfig, IConsole *pConsole, IEngine *pEngine, int ServerPort, unsigned SixupSecurityToken);
	void Update() override;
	void OnConfigChange() override;
	bool OnPacket(CNetChunk *pPacket) override;
	void OnNewInfo(const char *pInfo) override;
};

bool CRegister::StatusFromString(int *pResult, const char *pString)
{
	if(str_comp(pString, "success") == 0)
	{
		*pResult = STATUS_OK;
	}
	else if(str_comp(pString, "need_challenge") == 0)
	{
		*pResult = STATUS_NEEDCHALLENGE;
	}
	else if(str_comp(pString, "need_info") == 0)
	{
		*pResult = STATUS_NEEDINFO;
	}
	else
	{
		*pResult = -1;
		return true;
	}
	return false;
}

bool CRegister::ProtocolFromUrl(int *pResult, const char *pUrl)
{
	// 1234567890123
	// tw-0.6+udp://
	if(str_length(pUrl) < 13)
	{
		*pResult = -1;
		return true;
	}
	bool Ipv6 = pUrl[13] == '[';
	if(str_startswith(pUrl, "tw-0.6+udp://"))
	{
		*pResult = Ipv6 ? PROTOCOL_TW6_IPV6 : PROTOCOL_TW6_IPV4;
	}
	else if(str_startswith(pUrl, "tw-0.7+udp://"))
	{
		*pResult = Ipv6 ? PROTOCOL_TW7_IPV6 : PROTOCOL_TW7_IPV4;
	}
	else
	{
		*pResult = -1;
		return true;
	}
	return false;
}

const char *CRegister::ProtocolToScheme(int Protocol)
{
	switch(Protocol)
	{
	case PROTOCOL_TW6_IPV6: return "tw-0.6+udp://";
	case PROTOCOL_TW6_IPV4: return "tw-0.6+udp://";
	case PROTOCOL_TW7_IPV6: return "tw-0.7+udp://";
	case PROTOCOL_TW7_IPV4: return "tw-0.7+udp://";
	}
	dbg_assert(false, "invalid protocol");
	dbg_break();
}

const char *CRegister::ProtocolToString(int Protocol)
{
	switch(Protocol)
	{
	case PROTOCOL_TW6_IPV6: return "tw0.6/ipv6";
	case PROTOCOL_TW6_IPV4: return "tw0.6/ipv4";
	case PROTOCOL_TW7_IPV6: return "tw0.7/ipv6";
	case PROTOCOL_TW7_IPV4: return "tw0.7/ipv4";
	}
	dbg_assert(false, "invalid protocol");
	dbg_break();
}

bool CRegister::ProtocolFromString(int *pResult, const char *pString)
{
	if(str_comp(pString, "tw0.6/ipv6") == 0)
	{
		*pResult = PROTOCOL_TW6_IPV6;
	}
	else if(str_comp(pString, "tw0.6/ipv4") == 0)
	{
		*pResult = PROTOCOL_TW6_IPV4;
	}
	else if(str_comp(pString, "tw0.7/ipv6") == 0)
	{
		*pResult = PROTOCOL_TW7_IPV6;
	}
	else if(str_comp(pString, "tw0.7/ipv4") == 0)
	{
		*pResult = PROTOCOL_TW7_IPV4;
	}
	else
	{
		*pResult = -1;
		return true;
	}
	return false;
}

const char *CRegister::ProtocolToSystem(int Protocol)
{
	switch(Protocol)
	{
	case PROTOCOL_TW6_IPV6: return "register/6/ipv6";
	case PROTOCOL_TW6_IPV4: return "register/6/ipv4";
	case PROTOCOL_TW7_IPV6: return "register/7/ipv6";
	case PROTOCOL_TW7_IPV4: return "register/7/ipv4";
	}
	dbg_assert(false, "invalid protocol");
	dbg_break();
}

IPRESOLVE CRegister::ProtocolToIpresolve(int Protocol)
{
	switch(Protocol)
	{
	case PROTOCOL_TW6_IPV6: return IPRESOLVE::V6;
	case PROTOCOL_TW6_IPV4: return IPRESOLVE::V4;
	case PROTOCOL_TW7_IPV6: return IPRESOLVE::V6;
	case PROTOCOL_TW7_IPV4: return IPRESOLVE::V4;
	}
	dbg_assert(false, "invalid protocol");
	dbg_break();
}

void CRegister::ConchainOnConfigChange(IConsole::IResult *pResult, void *pUserData, IConsole::FCommandCallback pfnCallback, void *pCallbackUserData)
{
	pfnCallback(pResult, pCallbackUserData);
	if(pResult->NumArguments())
	{
		((CRegister *)pUserData)->OnConfigChange();
	}
}

void CRegister::CProtocol::SendRegister()
{
	int64_t Now = time_get();
	int64_t Freq = time_freq();

	char aAddress[64];
	str_format(aAddress, sizeof(aAddress), "%sconnecting-address.invalid:%d", ProtocolToScheme(m_Protocol), m_pParent->m_ServerPort);

	char aSecret[UUID_MAXSTRSIZE];
	FormatUuid(m_pParent->m_Secret, aSecret, sizeof(aSecret));

	lock_wait(m_pShared->m_pGlobal->m_Lock);
	int InfoSerial = m_pShared->m_pGlobal->m_InfoSerial;
	bool SendInfo = InfoSerial > m_pShared->m_pGlobal->m_LatestSuccessfulInfoSerial;
	lock_unlock(m_pShared->m_pGlobal->m_Lock);

	// TODO: Don't send info if the master already knows it.
	std::unique_ptr<CHttpRequest> pRegister;
	if(SendInfo)
	{
		pRegister = HttpPostJson(m_pParent->m_pConfig->m_SvRegisterUrl, m_pParent->m_aServerInfo);
	}
	else
	{
		pRegister = HttpPost(m_pParent->m_pConfig->m_SvRegisterUrl, (unsigned char *)"", 0);
	}
	pRegister->HeaderString("Address", aAddress);
	pRegister->HeaderString("Secret", aSecret);
	if(m_Protocol == PROTOCOL_TW7_IPV6 || m_Protocol == PROTOCOL_TW7_IPV4)
	{
		pRegister->HeaderString("Connless-Request-Token", m_pParent->m_aConnlessRequestTokenHex);
	}
	if(m_HaveChallengeToken)
	{
		pRegister->HeaderString("Challenge-Token", m_aChallengeToken);
	}
	pRegister->HeaderInt("Info-Serial", InfoSerial);
	pRegister->LogProgress(HTTPLOG::FAILURE);
	pRegister->IpResolve(ProtocolToIpresolve(m_Protocol));

	lock_wait(m_pShared->m_Lock);
	if(!m_pShared->m_Registered)
	{
		log_info(ProtocolToSystem(m_Protocol), "registering...");
	}
	lock_unlock(m_pShared->m_Lock);
	m_pParent->m_pEngine->AddJob(std::make_shared<CJob>(m_Protocol, m_NumTotalRequests, InfoSerial, m_pShared, std::move(pRegister)));
	m_NewChallengeToken = false;
	m_NumTotalRequests += 1;

	m_PrevRegister = Now;
	m_NextRegister = Now + 15 * Freq;
}

CRegister::CProtocol::CProtocol(CRegister *pParent, int Protocol) :
	m_pParent(pParent),
	m_Protocol(Protocol),
	m_pShared(std::make_shared<CShared>(pParent->m_pGlobal))
{
}

void CRegister::CProtocol::CheckChallengeStatus()
{
	lock_wait(m_pShared->m_Lock);
	// No requests in flight?
	if(m_pShared->m_LatestResponseIndex == m_NumTotalRequests - 1)
	{
		switch(m_pShared->m_LatestResponseStatus)
		{
		case STATUS_NEEDCHALLENGE:
			if(m_NewChallengeToken)
			{
				// Immediately resend if we got the token.
				m_NextRegister = time_get();
			}
			break;
		case STATUS_NEEDINFO:
			// Act immediately if the master requests more info.
			m_NextRegister = time_get();
			break;
		}
	}
	lock_unlock(m_pShared->m_Lock);
}

void CRegister::CProtocol::Update()
{
	lock_wait(m_pShared->m_Lock);
	if(m_pShared->m_LatestResponseIndex == m_NumTotalRequests - 1)
	{
		m_pShared->m_Registered = m_pShared->m_LatestResponseStatus == STATUS_OK;
	}
	lock_unlock(m_pShared->m_Lock);
	CheckChallengeStatus();
	if(time_get() >= m_NextRegister)
	{
		SendRegister();
	}
}

void CRegister::CProtocol::OnToken(const char *pToken)
{
	m_NewChallengeToken = true;
	m_HaveChallengeToken = true;
	str_copy(m_aChallengeToken, pToken, sizeof(m_aChallengeToken));

	CheckChallengeStatus();
	if(time_get() >= m_NextRegister)
	{
		SendRegister();
	}
}

void CRegister::CProtocol::CJob::Run()
{
	IEngine::RunJobBlocking(m_pRegister.get());
	if(m_pRegister->State() != HTTP_DONE)
	{
		// TODO: log the error response content from master
		// TODO: exponential backoff
		log_error(ProtocolToSystem(m_Protocol), "error response from master");
		return;
	}
	json_value *pJson = m_pRegister->ResultJson();
	if(!pJson)
	{
		log_error(ProtocolToSystem(m_Protocol), "non-JSON response from master");
		return;
	}
	const json_value &Json = *pJson;
	const json_value &StatusString = Json["status"];
	if(StatusString.type != json_string)
	{
		json_value_free(pJson);
		log_error(ProtocolToSystem(m_Protocol), "invalid JSON response from master");
		return;
	}
	int Status;
	if(StatusFromString(&Status, StatusString))
	{
		log_error(ProtocolToSystem(m_Protocol), "invalid status from master: %s", (const char *)StatusString);
		json_value_free(pJson);
		return;
	}
	lock_wait(m_pShared->m_Lock);
	if(Status != STATUS_OK || !m_pShared->m_Registered)
	{
		log_debug(ProtocolToSystem(m_Protocol), "status: %s", (const char *)StatusString);
	}
	json_value_free(pJson);
	if(m_Index > m_pShared->m_LatestResponseIndex)
	{
		m_pShared->m_LatestResponseIndex = m_Index;
		m_pShared->m_LatestResponseStatus = Status;
	}
	lock_unlock(m_pShared->m_Lock);
	if(Status == STATUS_OK)
	{
		lock_wait(m_pShared->m_pGlobal->m_Lock);
		if(m_InfoSerial > m_pShared->m_pGlobal->m_LatestSuccessfulInfoSerial)
		{
			m_pShared->m_pGlobal->m_LatestSuccessfulInfoSerial = m_InfoSerial;
		}
		lock_unlock(m_pShared->m_pGlobal->m_Lock);
	}
	else if(Status == STATUS_NEEDINFO)
	{
		lock_wait(m_pShared->m_pGlobal->m_Lock);
		if(m_InfoSerial == m_pShared->m_pGlobal->m_LatestSuccessfulInfoSerial)
		{
			// Tell other requests that they need to send the info again.
			m_pShared->m_pGlobal->m_LatestSuccessfulInfoSerial -= 1;
		}
		lock_unlock(m_pShared->m_pGlobal->m_Lock);
	}
}

CRegister::CRegister(CConfig *pConfig, IConsole *pConsole, IEngine *pEngine, int ServerPort, unsigned SixupSecurityToken) :
	m_pConfig(pConfig),
	m_pConsole(pConsole),
	m_pEngine(pEngine),
	m_ServerPort(ServerPort),
	m_aProtocols{
		CProtocol(this, PROTOCOL_TW6_IPV6),
		CProtocol(this, PROTOCOL_TW6_IPV4),
		CProtocol(this, PROTOCOL_TW7_IPV6),
		CProtocol(this, PROTOCOL_TW7_IPV4),
	}
{
	const int HEADER_LEN = sizeof(SERVERBROWSE_CHALLENGE);
	mem_copy(m_aVerifyPacket, SERVERBROWSE_CHALLENGE, HEADER_LEN);
	FormatUuid(m_Secret, m_aVerifyPacket + HEADER_LEN, sizeof(m_aVerifyPacket) - HEADER_LEN);

	// The DDNet code uses the `unsigned` security token in memory byte order.
	unsigned char TokenBytes[4];
	mem_copy(TokenBytes, &SixupSecurityToken, sizeof(TokenBytes));
	str_format(m_aConnlessRequestTokenHex, sizeof(m_aConnlessRequestTokenHex), "%08x", bytes_be_to_uint(TokenBytes));

	m_pConsole->Chain("sv_register", ConchainOnConfigChange, this);
	m_pConsole->Chain("sv_sixup", ConchainOnConfigChange, this);
}

void CRegister::Update()
{
	if(!m_GotServerInfo)
	{
		return;
	}
	for(int i = 0; i < NUM_PROTOCOLS; i++)
	{
		if(!m_aProtocolEnabled[i])
		{
			continue;
		}
		m_aProtocols[i].Update();
	}
}

void CRegister::OnConfigChange()
{
	const char *pProtocols = m_pConfig->m_SvRegister;
	if(str_comp(pProtocols, "1") == 0)
	{
		for(auto &Enabled : m_aProtocolEnabled)
		{
			Enabled = true;
		}
	}
	else if(str_comp(pProtocols, "0") == 0)
	{
		for(auto &Enabled : m_aProtocolEnabled)
		{
			Enabled = false;
		}
	}
	else
	{
		for(auto &Enabled : m_aProtocolEnabled)
		{
			Enabled = false;
		}
		char aBuf[16];
		while((pProtocols = str_next_token(pProtocols, ",", aBuf, sizeof(aBuf))))
		{
			int Protocol;
			if(str_comp(aBuf, "ipv6") == 0)
			{
				m_aProtocolEnabled[PROTOCOL_TW6_IPV6] = true;
				m_aProtocolEnabled[PROTOCOL_TW7_IPV6] = true;
			}
			else if(str_comp(aBuf, "ipv4") == 0)
			{
				m_aProtocolEnabled[PROTOCOL_TW6_IPV4] = true;
				m_aProtocolEnabled[PROTOCOL_TW7_IPV4] = true;
			}
			else if(str_comp(aBuf, "tw0.6") == 0)
			{
				m_aProtocolEnabled[PROTOCOL_TW6_IPV6] = true;
				m_aProtocolEnabled[PROTOCOL_TW6_IPV4] = true;
			}
			else if(str_comp(aBuf, "tw0.7") == 0)
			{
				m_aProtocolEnabled[PROTOCOL_TW7_IPV6] = true;
				m_aProtocolEnabled[PROTOCOL_TW7_IPV4] = true;
			}
			else if(!ProtocolFromString(&Protocol, aBuf))
			{
				m_aProtocolEnabled[Protocol] = true;
			}
			else
			{
				log_warn("register", "unknown protocol '%s'", aBuf);
				continue;
			}
		}
	}
	if(!m_pConfig->m_SvSixup)
	{
		m_aProtocolEnabled[PROTOCOL_TW7_IPV6] = false;
		m_aProtocolEnabled[PROTOCOL_TW7_IPV4] = false;
	}
	int RegisterExtraLength = str_length(m_pConfig->m_SvRegisterExtra);
	json_value *pRegisterExtra = json_parse(m_pConfig->m_SvRegisterExtra, RegisterExtraLength);
	bool Valid = pRegisterExtra && pRegisterExtra->type == json_object && m_pConfig->m_SvRegisterExtra[0] == '{' && m_pConfig->m_SvRegisterExtra[RegisterExtraLength - 1] == '}';
	bool Empty = !Valid || pRegisterExtra->u.object.length == 0;
	json_value_free(pRegisterExtra);
	if(!Empty)
	{
		str_copy(m_aRegisterExtra, m_pConfig->m_SvRegisterExtra, sizeof(m_aRegisterExtra));
		m_aRegisterExtra[0] = ',';
		m_aRegisterExtra[RegisterExtraLength - 1] = 0;
	}
	else
	{
		str_copy(m_aRegisterExtra, "", sizeof(m_aRegisterExtra));
	}
	if(!Valid)
	{
		log_error("register", "invalid sv_register_extra, not a JSON object or doesn't start/end with {}: '%s'", m_pConfig->m_SvRegisterExtra);
	}
}

bool CRegister::OnPacket(CNetChunk *pPacket)
{
	if((pPacket->m_Flags & NETSENDFLAG_CONNLESS) == 0)
	{
		return false;
	}
	if(pPacket->m_DataSize >= (int)sizeof(m_aVerifyPacket) &&
		mem_comp(pPacket->m_pData, m_aVerifyPacket, sizeof(m_aVerifyPacket)) == 0)
	{
		CUnpacker Unpacker;
		Unpacker.Reset(pPacket->m_pData, pPacket->m_DataSize);
		Unpacker.GetRaw(sizeof(m_aVerifyPacket));
		const char *pAddressUrl = Unpacker.GetString(0);
		const char *pToken = Unpacker.GetString(0);
		if(Unpacker.Error())
		{
			log_error("register", "got errorneous challenge packet from master");
			return true;
		}

		log_debug("register", "got challenge token, addr='%s' token='%s'", pAddressUrl, pToken);
		int Protocol;
		if(ProtocolFromUrl(&Protocol, pAddressUrl))
		{
			log_error("register", "got challenge packet with unknown protocol");
			return true;
		}
		m_aProtocols[Protocol].OnToken(pToken);
		return true;
	}
	return false;
}

void CRegister::OnNewInfo(const char *pInfo)
{
	log_trace("register", "info: %s", pInfo);
	if(m_GotServerInfo && str_comp(m_aServerInfo, pInfo) == 0)
	{
		return;
	}

	m_GotServerInfo = true;
	str_copy(m_aServerInfo, pInfo, sizeof(m_aServerInfo));
	lock_wait(m_pGlobal->m_Lock);
	m_pGlobal->m_InfoSerial += 1;
	lock_unlock(m_pGlobal->m_Lock);

	// Immediately send new info if it changes, but at most once per second.
	int64_t Now = time_get();
	int64_t Freq = time_freq();
	int64_t MaximumPrevRegister = -1;
	int64_t MinimumNextRegister = -1;
	int MinimumNextRegisterProtocol = -1;
	for(int i = 0; i < NUM_PROTOCOLS; i++)
	{
		if(!m_aProtocolEnabled[i])
		{
			continue;
		}
		if(m_aProtocols[i].m_NextRegister == -1)
		{
			m_aProtocols[i].m_NextRegister = Now;
			continue;
		}
		if(m_aProtocols[i].m_PrevRegister > MaximumPrevRegister)
		{
			MaximumPrevRegister = m_aProtocols[i].m_PrevRegister;
		}
		if(MinimumNextRegisterProtocol == -1 || m_aProtocols[i].m_NextRegister < MinimumNextRegister)
		{
			MinimumNextRegisterProtocol = i;
			MinimumNextRegister = m_aProtocols[i].m_NextRegister;
		}
	}
	for(int i = 0; i < NUM_PROTOCOLS; i++)
	{
		if(!m_aProtocolEnabled[i])
		{
			continue;
		}
		if(i == MinimumNextRegisterProtocol)
		{
			m_aProtocols[i].m_NextRegister = std::min(m_aProtocols[i].m_NextRegister, MaximumPrevRegister + Freq);
		}
		if(Now >= m_aProtocols[i].m_NextRegister)
		{
			m_aProtocols[i].SendRegister();
		}
	}
}

IRegister *CreateRegister(CConfig *pConfig, IConsole *pConsole, IEngine *pEngine, int ServerPort, unsigned SixupSecurityToken)
{
	return new CRegister(pConfig, pConsole, pEngine, ServerPort, SixupSecurityToken);
}
