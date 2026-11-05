use std::collections::HashSet;
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy)]
pub struct LevelSpec {
    pub source_map: &'static str,
    pub coop_map: &'static str,
    pub identity: u8,
    pub spawn_offset: (f32, f32, f32),
}

pub static SP_COOP_LEVELS: &[LevelSpec] = &[
    LevelSpec {
        source_map: "01_Lighthouse",
        coop_map: "01_Lighthouse_COOP",
        identity: 203,
        spawn_offset: (80.0, -60.0, 9.6),
    },
    LevelSpec {
        source_map: "02_CargoShip",
        coop_map: "02_CargoShip_COOP",
        identity: 204,
        spawn_offset: (-18.0, 80.0, 8.0),
    },
    LevelSpec {
        source_map: "03_Bank",
        coop_map: "03_Bank_COOP",
        identity: 205,
        spawn_offset: (-55.0, -65.0, 8.0),
    },
    LevelSpec {
        source_map: "04_Penthouse",
        coop_map: "04_Penthouse_COOP",
        identity: 206,
        spawn_offset: (-85.0, -20.0, 8.0),
    },
    LevelSpec {
        source_map: "05_Displace01",
        coop_map: "05_Displace01_COOP",
        identity: 207,
        spawn_offset: (0.0, -85.0, 8.0),
    },
    LevelSpec {
        source_map: "06_Hokkaido",
        coop_map: "06_Hokkaido_COOP",
        identity: 208,
        spawn_offset: (-35.0, -80.0, 8.0),
    },
    LevelSpec {
        source_map: "07_Battery",
        coop_map: "07_Battery_COOP",
        identity: 209,
        spawn_offset: (70.0, 8.0, 4.0),
    },
    LevelSpec {
        source_map: "08_SeoulOne",
        coop_map: "08_SeoulOne_COOP",
        identity: 210,
        spawn_offset: (75.0, -10.0, 6.0),
    },
    LevelSpec {
        source_map: "09_SeoulTwo",
        coop_map: "09_SeoulTwo_COOP",
        identity: 211,
        spawn_offset: (0.0, -85.0, 8.0),
    },
    LevelSpec {
        source_map: "10_BathHouse",
        coop_map: "10_BathHouse_COOP",
        identity: 212,
        spawn_offset: (-85.0, 5.0, 8.0),
    },
    LevelSpec {
        source_map: "11_KokuboSosho",
        coop_map: "11_KokuboSosho_COOP",
        identity: 213,
        spawn_offset: (-25.0, 80.0, 6.0),
    },
];

pub static VANILLA_COOP_STEMS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    let mut s = HashSet::new();
    s.insert("00_training_coop");
    s.insert("01_panama");
    s.insert("02_seoulthree");
    s.insert("03_chembunker");
    s.insert("04_gcs");
    s.insert("05_nuclearplant");
    s.insert("07_unhq");
    s
});

pub const LANG_EXTS: &[&str] = &["int", "fra", "deu", "esp", "ita"];

pub const DEFAULT_COOP_EMISSION_MANAGER: &str = "\
[Echelon.EMissionManager]
StartupAttach=EAttachType_Launcher
AttachForegrip=1
AttachLauncher=1
AttachSniper=0
AttachShotgun=0
AmmoClipSC20k=5
AmmoClip57=2
AmmoClipShotgun=0
AmmoClipSniper=0
StickyCamera=3
StickyShocker=3
GazGrenade=3
RingAirfoilRound=3
FragGrenade=2
FlashGrenade=2
SmokeGrenade=2
InfraRedStressGen=0
WallMine=0
";

pub const DEFAULT_COOP_LOADOUTS: &str = "\
[LOADOUT_HOST]
StartupAttach=EAttachType_Launcher
AttachForegrip=1
AttachLauncher=1
AttachSniper=0
AttachShotgun=0
AmmoClipSC20k=5
AmmoClip57=2
AmmoClipShotgun=0
AmmoClipSniper=0
StickyCamera=2
StickyShocker=3
GazGrenade=1
RingAirfoilRound=3
FragGrenade=0
FlashGrenade=2
SmokeGrenade=2
InfraRedStressGen=0
WallMine=0

[LOADOUT_CLIENT]
StartupAttach=EAttachType_Launcher
AttachForegrip=1
AttachLauncher=1
AttachSniper=0
AttachShotgun=0
AmmoClipSC20k=5
AmmoClip57=2
AmmoClipShotgun=0
AmmoClipSniper=0
StickyCamera=2
StickyShocker=3
GazGrenade=1
RingAirfoilRound=3
FragGrenade=0
FlashGrenade=2
SmokeGrenade=2
InfraRedStressGen=0
WallMine=0

[LOADOUT_HOST_ELITE]
StartupAttach=EAttachType_Launcher
AttachForegrip=1
AttachLauncher=1
AttachSniper=0
AttachShotgun=0
AmmoClipSC20k=3
AmmoClip57=1
AmmoClipShotgun=0
AmmoClipSniper=0
StickyCamera=1
StickyShocker=2
GazGrenade=0
RingAirfoilRound=2
FragGrenade=0
FlashGrenade=1
SmokeGrenade=1
InfraRedStressGen=0
WallMine=0

[LOADOUT_CLIENT_ELITE]
StartupAttach=EAttachType_Launcher
AttachForegrip=1
AttachLauncher=1
AttachSniper=0
AttachShotgun=0
AmmoClipSC20k=3
AmmoClip57=1
AmmoClipShotgun=0
AmmoClipSniper=0
StickyCamera=1
StickyShocker=2
GazGrenade=0
RingAirfoilRound=2
FragGrenade=0
FlashGrenade=1
SmokeGrenade=1
InfraRedStressGen=0
WallMine=0
";
