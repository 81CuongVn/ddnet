/* (c) Magnus Auvinen. See licence.txt in the root of the distribution for more information. */
/* If you are missing that file, acquire a complete release at teeworlds.com.                */
#ifndef GAME_CLIENT_COMPONENTS_HUD_H
#define GAME_CLIENT_COMPONENTS_HUD_H
#include <game/client/component.h>

struct SScoreInfo
{
	SScoreInfo()
	{
		Reset();
	}

	void Reset()
	{
		m_TextRankContainerIndex = m_TextScoreContainerIndex = m_RoundRectQuadContainerIndex = m_OptionalNameTextContainerIndex = -1;
		m_aScoreText[0] = 0;
		m_aRankText[0] = 0;
		m_aPlayerNameText[0] = 0;
		m_ScoreTextWidth = 0.f;
		m_Initialized = false;
	}

	int m_TextRankContainerIndex;
	int m_TextScoreContainerIndex;
	float m_ScoreTextWidth;
	char m_aScoreText[16];
	char m_aRankText[16];
	char m_aPlayerNameText[MAX_NAME_LENGTH];
	int m_RoundRectQuadContainerIndex;
	int m_OptionalNameTextContainerIndex;

	bool m_Initialized;
};

class CHud : public CComponent
{
	float m_Width, m_Height;
	float m_FrameTimeAvg;

	int m_HudQuadContainerIndex;
	SScoreInfo m_aScoreInfo[2];
	int m_FPSTextContainerIndex;

	void RenderCursor();

	void RenderTextInfo();
	void RenderConnectionWarning();
	void RenderTeambalanceWarning();
	void RenderVoting();

	void PrepareAmmoHealthAndArmorQuads();
	void RenderAmmoHealthAndArmor(const CNetObj_Character *pCharacter);

	void PreparePlayerStateQuads();
	void RenderPlayerState(const int ClientID);
	void RenderDummyActions();
	void RenderMovementInformation(const int ClientID);

	void RenderGameTimer();
	void RenderPauseNotification();
	void RenderSuddenDeath();
	void RenderScoreHud();
	void RenderSpectatorHud();
	void RenderWarmupTimer();
	void RenderLocalTime(float x);

	static constexpr float MOVEMENT_INFORMATION_LINE_HEIGHT = 8.0f;

public:
	CHud();
	virtual int Sizeof() const override { return sizeof(*this); }

	void ResetHudContainers();
	virtual void OnWindowResize() override;
	virtual void OnReset() override;
	virtual void OnRender() override;
	virtual void OnInit() override;

	// DDRace

	virtual void OnMessage(int MsgType, void *pRawMsg) override;
	void RenderNinjaBarPos(float x, const float y, const float width, const float height, float Progress, float Alpha = 1.0f);
	void OnHudChange();

private:
	void RenderRecord();
	void RenderDDRaceEffects();
	float m_CheckpointDiff;
	float m_ServerRecord;
	float m_PlayerRecord[NUM_DUMMIES];
	int m_DDRaceTime;
	int m_LastReceivedTimeTick;
	int m_CheckpointTick;
	bool m_FinishTime;
	bool m_DDRaceTimeReceived;

	inline float GetMovementInformationBoxHeight();
	inline int GetDigitsIndex(int Value, int Max);

	// Quad Offsets
	int m_AmmoOffset[NUM_WEAPONS];
	int m_HealthOffset;
	int m_EmptyHealthOffset;
	int m_ArmorOffset;
	int m_EmptyArmorOffset;
	int m_CursorOffset[NUM_WEAPONS];
	int m_FlagOffset;
	int m_AirjumpOffset;
	int m_AirjumpEmptyOffset;
	int m_WeaponHammerOffset;
	int m_WeaponGunOffset;
	int m_WeaponShotgunOffset;
	int m_WeaponGrenadeOffset;
	int m_WeaponLaserOffset;
	int m_WeaponNinjaOffset;
	int m_EndlessJumpOffset;
	int m_EndlessHookOffset;
	int m_JetpackOffset;
	int m_TeleportGrenadeOffset;
	int m_TeleportGunOffset;
	int m_TeleportLaserOffset;
	int m_SoloOffset;
	int m_NoCollisionOffset;
	int m_NoHookHitOffset;
	int m_NoHammerHitOffset;
	int m_NoShotgunHitOffset;
	int m_NoGrenadeHitOffset;
	int m_NoLaserHitOffset;
	int m_DeepFrozenOffset;
	int m_LiveFrozenOffset;
	int m_DummyHammerOffset;
	int m_DummyCopyOffset;
	int m_PracticeModeOffset;
};

#endif
