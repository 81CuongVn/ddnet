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
		STATUS_FAILED,
		STATUS_NEEDCHALLENGE,

		PROTOCOL_IPV6 = 0,
		PROTOCOL_IPV4,
		NUM_PROTOCOLS,
	};

	static int StatusFromString(int *pResult, const char *pString);
	static int ProtocolFromAddr(const NETADDR &Addr);
	static const char *ProtocolToString(int Protocol);
	static int ProtocolFromString(int *pResult, const char *pString);
	static const char *ProtocolToSystem(int Protocol);
	static IPRESOLVE ProtocolToIpresolve(int Protocol);

	static void ConchainSvRegister(IConsole::IResult *pResult, void *pUserData, IConsole::FCommandCallback pfnCallback, void *pCallbackUserData);

	class CProtocol
	{
		class CShared
		{
		public:
			~CShared()
			{
				lock_destroy(m_Lock);
			}

			LOCK m_Lock = lock_create();
			int m_LatestResponseStatus GUARDED_BY(m_Lock) = STATUS_NONE;
			int m_LatestResponseIndex GUARDED_BY(m_Lock) = -1;
		};

		class CJob : public IJob
		{
			int m_Protocol;
			int m_Index;
			std::shared_ptr<CShared> m_pShared;
			std::unique_ptr<CHttpRequest> m_pRegister;
			virtual void Run();

		public:
			CJob(int Protocol, int Index, std::shared_ptr<CShared> pShared, std::unique_ptr<CHttpRequest> &&pRegister) :
				m_Protocol(Protocol),
				m_Index(Index),
				m_pShared(std::move(pShared)),
				m_pRegister(std::move(pRegister))
			{
			}
			virtual ~CJob() = default;
		};

		CRegister *m_pParent;
		int m_Protocol;

		std::shared_ptr<CShared> m_pShared = std::make_shared<CShared>();
		int m_NumTotalRequests = 0;
		bool m_NewChallengeToken = false;
		char m_aChallengeTokenJson[128] = {0};

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

	bool m_aProtocolEnabled[NUM_PROTOCOLS] = {true, true};
	CProtocol m_aProtocols[NUM_PROTOCOLS];

	char m_aVerifyPacket[sizeof(SERVERBROWSE_CHALLENGE) + UUID_MAXSTRSIZE];
	CUuid m_Secret = RandomUuid();
	bool m_GotServerInfo = false;
	int m_InfoSerial = -1;
	char m_aServerInfo[1024];

	void UpdateFromConfig();

public:
	CRegister(CConfig *pConfig, IConsole *pConsole, IEngine *pEngine, int ServerPort);
	void Update();
	bool OnPacket(CNetChunk *pPacket);
	void OnNewInfo(const char *pInfo);
};

int CRegister::StatusFromString(int *pResult, const char *pString)
{
	if(str_comp(pString, "success") == 0)
	{
		*pResult = STATUS_OK;
	}
	else if(str_comp(pString, "need_challenge") == 0)
	{
		*pResult = STATUS_NEEDCHALLENGE;
	}
	else
	{
		*pResult = -1;
		return true;
	}
	return false;
}

int CRegister::ProtocolFromAddr(const NETADDR &Addr)
{
	switch(Addr.type)
	{
	case NETTYPE_IPV6: return PROTOCOL_IPV6;
	case NETTYPE_IPV4: return PROTOCOL_IPV4;
	}
	dbg_assert(false, "invalid nettype");
	dbg_break();
}

const char *CRegister::ProtocolToString(int Protocol)
{
	switch(Protocol)
	{
	case PROTOCOL_IPV6: return "ipv6";
	case PROTOCOL_IPV4: return "ipv4";
	}
	dbg_assert(false, "invalid protocol");
	dbg_break();
}

int CRegister::ProtocolFromString(int *pResult, const char *pString)
{
	if(str_comp(pString, "ipv6") == 0)
	{
		*pResult = PROTOCOL_IPV6;
	}
	else if(str_comp(pString, "ipv4") == 0)
	{
		*pResult = PROTOCOL_IPV4;
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
	case PROTOCOL_IPV6: return "register/ipv6";
	case PROTOCOL_IPV4: return "register/ipv4";
	}
	dbg_assert(false, "invalid protocol");
	dbg_break();
}

IPRESOLVE CRegister::ProtocolToIpresolve(int Protocol)
{
	switch(Protocol)
	{
	case PROTOCOL_IPV6: return IPRESOLVE::V6;
	case PROTOCOL_IPV4: return IPRESOLVE::V4;
	}
	dbg_assert(false, "invalid protocol");
	dbg_break();
}

void CRegister::ConchainSvRegister(IConsole::IResult *pResult, void *pUserData, IConsole::FCommandCallback pfnCallback, void *pCallbackUserData)
{
	pfnCallback(pResult, pCallbackUserData);
	if(pResult->NumArguments())
	{
		((CRegister *)pUserData)->UpdateFromConfig();
	}
}

void CRegister::CProtocol::SendRegister()
{
	int64_t Now = time_get();
	int64_t Freq = time_freq();

	char aSecret[UUID_MAXSTRSIZE];
	FormatUuid(m_pParent->m_Secret, aSecret, sizeof(aSecret));

	char aInfoSerial[16];
	// Make sure the info serial sorts alphabetically. Start with a0 to a9,
	// continue with b10 to b99, c100 to c999 and so on.
	str_format(aInfoSerial + 1, sizeof(aInfoSerial) - 1, "%d", m_pParent->m_InfoSerial);
	aInfoSerial[0] = 'a' + str_length(aInfoSerial + 1) - 1;

	// TODO: Don't send info if the master already knows it.
	char aJson[4096];
	str_format(aJson, sizeof(aJson),
		"{"
		"\"address\":\"tw-0.6+udp://connecting-address.invalid:%d\","
		"\"secret\":\"%s\","
		"%s"
		"\"info_serial\":\"%s\","
		"\"info\":%s"
		"}",
		m_pParent->m_ServerPort,
		aSecret,
		m_aChallengeTokenJson,
		aInfoSerial,
		m_pParent->m_aServerInfo);

	std::unique_ptr<CHttpRequest> pRegister = HttpPostJson(m_pParent->m_pConfig->m_SvRegisterUrl, aJson);
	pRegister->LogProgress(HTTPLOG::FAILURE);
	pRegister->IpResolve(ProtocolToIpresolve(m_Protocol));

	log_debug(ProtocolToSystem(m_Protocol), "registering...");
	m_pParent->m_pEngine->AddJob(std::make_shared<CJob>(m_Protocol, m_NumTotalRequests, m_pShared, std::move(pRegister)));
	m_NewChallengeToken = false;
	m_NumTotalRequests += 1;

	m_PrevRegister = Now;
	m_NextRegister = Now + 15 * Freq;
}

CRegister::CProtocol::CProtocol(CRegister *pParent, int Protocol) :
	m_pParent(pParent),
	m_Protocol(Protocol)
{
}

void CRegister::CProtocol::CheckChallengeStatus()
{
	if(!m_NewChallengeToken)
	{
		return;
	}
	lock_wait(m_pShared->m_Lock);
	if(m_pShared->m_LatestResponseStatus == STATUS_NEEDCHALLENGE && m_pShared->m_LatestResponseIndex == m_NumTotalRequests - 1)
	{
		m_NextRegister = time_get();
	}
	lock_unlock(m_pShared->m_Lock);
}

void CRegister::CProtocol::Update()
{
	CheckChallengeStatus();
	if(time_get() >= m_NextRegister)
	{
		SendRegister();
	}
}

void CRegister::CProtocol::OnToken(const char *pToken)
{
	log_trace(ProtocolToSystem(m_Protocol), "got token: %s", pToken);
	m_NewChallengeToken = true;
	char aToken[64];
	str_format(m_aChallengeTokenJson, sizeof(m_aChallengeTokenJson), "\"challenge_token\":\"%s\",", EscapeJson(aToken, sizeof(aToken), pToken));

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
	log_debug(ProtocolToSystem(m_Protocol), "status: %s", (const char *)StatusString);
	json_value_free(pJson);
	lock_wait(m_pShared->m_Lock);
	if(m_Index > m_pShared->m_LatestResponseIndex)
	{
		m_pShared->m_LatestResponseIndex = m_Index;
		m_pShared->m_LatestResponseStatus = Status;
	}
	lock_unlock(m_pShared->m_Lock);
}

CRegister::CRegister(CConfig *pConfig, IConsole *pConsole, IEngine *pEngine, int ServerPort) :
	m_pConfig(pConfig),
	m_pConsole(pConsole),
	m_pEngine(pEngine),
	m_ServerPort(ServerPort),
	m_aProtocols{CProtocol(this, PROTOCOL_IPV6), CProtocol(this, PROTOCOL_IPV4)}
{
	const int HEADER_LEN = sizeof(SERVERBROWSE_CHALLENGE);
	mem_copy(m_aVerifyPacket, SERVERBROWSE_CHALLENGE, HEADER_LEN);
	FormatUuid(m_Secret, m_aVerifyPacket + HEADER_LEN, sizeof(m_aVerifyPacket) - HEADER_LEN);
	m_pConsole->Chain("sv_register", ConchainSvRegister, this);
}

void CRegister::UpdateFromConfig()
{
	const char *pProtocols = m_pConfig->m_SvRegister;
	if(str_comp(pProtocols, "1") == 0)
	{
		for(auto &Enabled : m_aProtocolEnabled)
		{
			Enabled = true;
		}
		return;
	}
	for(auto &Enabled : m_aProtocolEnabled)
	{
		Enabled = false;
	}
	if(str_comp(pProtocols, "0") == 0)
	{
		return;
	}
	char aBuf[16];
	while((pProtocols = str_next_token(pProtocols, ",", aBuf, sizeof(aBuf))))
	{
		int Protocol;
		if(ProtocolFromString(&Protocol, aBuf))
		{
			log_warn("register", "unknown protocol '%s'", aBuf);
			continue;
		}
		m_aProtocolEnabled[Protocol] = true;
	}
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

bool CRegister::OnPacket(CNetChunk *pPacket)
{
	if((pPacket->m_Flags & NETSENDFLAG_CONNLESS) == 0)
	{
		return false;
	}
	log_trace("register", "packet size=%d", pPacket->m_DataSize);
	if(pPacket->m_DataSize >= (int)sizeof(m_aVerifyPacket) &&
		mem_comp(pPacket->m_pData, m_aVerifyPacket, sizeof(m_aVerifyPacket)) == 0)
	{
		CUnpacker Unpacker;
		Unpacker.Reset(pPacket->m_pData, pPacket->m_DataSize);
		Unpacker.GetRaw(sizeof(m_aVerifyPacket));
		const char *pToken = Unpacker.GetString(0);
		if(Unpacker.Error())
		{
			return false;
		}

		m_aProtocols[ProtocolFromAddr(pPacket->m_Address)].OnToken(pToken);
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
	m_InfoSerial += 1;

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

IRegister *CreateRegister(CConfig *pConfig, IConsole *pConsole, IEngine *pEngine, int ServerPort)
{
	return new CRegister(pConfig, pConsole, pEngine, ServerPort);
}
