#include <iostream>
#include <fstream>
#include <thread>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <dlfcn.h>
#include <libgen.h>
#include <unwind.h>
#include <pthread.h>
#include <sstream>
#include <locale>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include "MTR/Includes.h"
#include "MTR/Tools.h"
#include "imgui/imgui.h"
#include "imgui/backends/imgui_impl_android.h"
#include "imgui/backends/imgui_impl_opengl3.h"
#include "MTR/StrEnc.h"
#include "MTR/Items.h"
#include "MTR/json.hpp"
#include "MTR/Iconcpp.h"
#include "MTR/ImguiPP.cpp"
#include "MTR/Menu.h"
#include "MTR/Vector3.hpp"
#include "MTR/Font.h"
#include "JostFont.h"
#include "MTR/Quaternion.hpp"
#include "MTR/Icon.h"
#include "MTR/oxorany.cpp"
using json = nlohmann::json;
bool Lobby = false;
bool EnableAntiban = false;
#define SLEEP_TIME 1000LL / 60LL
#include "SDK.hpp"
using namespace SDK;
#include <curl/curl.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <GLES/gl.h>
#include <GLES/glext.h>
#include <GLES/glplatform.h>
#include "MTR/obfuscate.h"
#ifndef skCrypt
#define skCrypt(s) (s)
#endif
#include "MTR/MemoryPatch.h"
#include "MTR/base64.h"
#include <cstring>
#include <string.h>
#include "MTR/Rect.h" 
#include "MTR/Dobby64/dobby.h"
#include "MTR/shadowhook/shadowhook.h"//shadowhook渲染
#include <MTR/And64InlineHook.hpp>
#include "MTR/patch/Logger.h"
#include "MTR/patch/Utils.h"
#include "MTR/patch/Macros.h" 
bool esp = false;
bool bullet = false;
bool customize = false;
bool extra = false;
bool loot = false;
bool memory = false;
bool autofire = false;
 // Define New time Date funtion //
#include <ctime>
#include <string>
#include <android/input.h>
#include "AImGui/AImGui.hpp"
#include "Loader.h"
#include "skin.h"
#include "value_object.h"
#include "AutoFeedback.h"
// ── skin_data.h (inlined) ────────────────────────────────────────────────────

// ── WirexCrash Debugger ──────────────────────────────────────────────────────
#include <signal.h>
#include <sys/stat.h>
#include <inttypes.h>

#define WIREX_DEBUG_DIR "/storage/emulated/0/Download/WirexDebag"

namespace WirexCrash {

struct BacktraceState {
    void **current;
    void **end;
};

static _Unwind_Reason_Code UnwindCallback(struct _Unwind_Context *context, void *arg) {
    BacktraceState *state = (BacktraceState *)arg;
    uintptr_t pc = _Unwind_GetIP(context);
    if (pc) {
        if (state->current == state->end) return _URC_END_OF_STACK;
        *state->current++ = (void *)pc;
    }
    return _URC_NO_REASON;
}

static size_t CaptureBacktrace(void **buffer, size_t max) {
    BacktraceState state = {buffer, buffer + max};
    _Unwind_Backtrace(UnwindCallback, &state);
    return state.current - buffer;
}

static std::string GetSignalName(int sig) {
    switch (sig) {
        case SIGSEGV: return "SIGSEGV (Segmentation Fault)";
        case SIGABRT: return "SIGABRT (Abort)";
        case SIGFPE:  return "SIGFPE (Floating Point Exception)";
        case SIGILL:  return "SIGILL (Illegal Instruction)";
        case SIGBUS:  return "SIGBUS (Bus Error)";
        case SIGTRAP: return "SIGTRAP (Trap)";
        case SIGPIPE: return "SIGPIPE (Broken Pipe)";
        default:      return "SIGNAL_" + std::to_string(sig);
    }
}

static std::string GetTimestamp() {
    time_t now = time(nullptr);
    struct tm *t = localtime(&now);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d_%H-%M-%S", t);
    return std::string(buf);
}

static void EnsureDir() {
    mkdir(WIREX_DEBUG_DIR, 0777);
    chmod(WIREX_DEBUG_DIR, 0777);
}

static void WriteCrashFile(int sig, siginfo_t *info, void * /*ctx*/) {
    EnsureDir();
    std::string ts = GetTimestamp();
    std::string path = std::string(WIREX_DEBUG_DIR) + "/crash_" + ts + ".txt";
    FILE *f = fopen(path.c_str(), "w");
    if (!f) return;

    fprintf(f, "========== WIREX CRASH REPORT ==========\n");
    fprintf(f, "Time       : %s\n", ts.c_str());
    fprintf(f, "Signal     : %s (%d)\n", GetSignalName(sig).c_str(), sig);
    if (info) {
        fprintf(f, "Fault Addr : %p\n", info->si_addr);
        fprintf(f, "Signal Code: %d\n", info->si_code);
        fprintf(f, "PID        : %d\n", info->si_pid);
    }
    fprintf(f, "\n---------- BACKTRACE ----------\n");

    const size_t MAX_FRAMES = 32;
    void *buffer[MAX_FRAMES];
    size_t count = CaptureBacktrace(buffer, MAX_FRAMES);
    for (size_t i = 0; i < count; i++) {
        Dl_info dlinfo;
        if (dladdr(buffer[i], &dlinfo)) {
            uintptr_t offset = (uintptr_t)buffer[i] - (uintptr_t)dlinfo.dli_fbase;
            const char *lib = dlinfo.dli_fname ? dlinfo.dli_fname : "?";
            const char *sym = dlinfo.dli_sname ? dlinfo.dli_sname : "?";
            fprintf(f, "#%02zu  pc 0x%08" PRIxPTR "  %s  (%s)\n", i, offset, lib, sym);
        } else {
            fprintf(f, "#%02zu  %p  (unknown)\n", i, buffer[i]);
        }
    }
    fprintf(f, "\n========== END OF REPORT ==========\n");
    fclose(f);
}

static struct sigaction g_OldHandlers[NSIG];

static void CrashHandler(int sig, siginfo_t *info, void *ctx) {
    WriteCrashFile(sig, info, ctx);
    sigaction(sig, &g_OldHandlers[sig], nullptr);
    raise(sig);
}

static void Init() {
    EnsureDir();
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags     = SA_SIGINFO | SA_ONSTACK;
    sa.sa_sigaction = CrashHandler;
    int sigs[] = {SIGSEGV, SIGABRT, SIGFPE, SIGILL, SIGBUS, SIGTRAP, SIGPIPE};
    for (int s : sigs) {
        sigaction(s, &sa, &g_OldHandlers[s]);
    }
}

} // namespace WirexCrash
// ── End WirexCrash Debugger ──────────────────────────────────────────────────


#define PATCH_LIB
#define HOOK_LIB(lib, addr, hook, orig)
#define HOOK_LIB_NO_ORIG(lib, offset, func)
#define HOOK_LIB_THUMB
class CModBase {};

class CWeapAttack : public CModBase {
public:
    DWORD Default = 0;
};

class CGunSkinSetting : public CModBase {
public:
    DWORD AKM = 1101001213, M16A4 = 1101002081, SCARL = 1101003188, M416 = 1101004046, GROZA = 1101005052,
          AUG = 1101006062, QBZ = 1101007046, M762 = 1101008126, HONEY = 0, ACE32 = 1101102017,
          UZI = 1102001024, UMP45 = 1102002136, VECTOR = 1102003080, TOMMY = 1102004018, PP19 = 1102005057,
          KAR98 = 1103001179, M24 = 1103002087, AWM = 1103003062, MINI14 = 1103006030, MK14 = 1103007020,
          AMR = 1103012010, M249 = 1105001048, DP28 = 1105002063, MG3 = 1101102017, DBS = 1104101001,
          S12K = 1104003027, XM1014 = 1104101001, PAN = 1108004356, KNIFE = 1108001057, KNIFE1 = 1108005050,
          P90 = 1102105012;
};

class CClothSetting : public CModBase {
public:
    DWORD SHIRT = 1405628, HAT = 0, PANT = 0, SHOE = 0, PARACHUTE = 0, HELMET1 = 1502001023,
          BACKPACK1 = 1501001220, HELMET2 = 1502002023, BACKPACK2 = 1501002220, HELMET3 = 1502003023,
          BACKPACK3 = 1501003220, GLIDER = 0;
};

class CVehicleSetting : public CModBase {
public:
    DWORD MOTOR = 1901047, COUPE = 1961015, UAZ = 1908067, DACIA = 1903075, MIRADO = 1915010, BUGGY = 1907054;
};

class CModSkinSetting {
public:
    DWORD dwPassword = 0xBEEF;
    bool bEnable = false, bGunSkin = false, bClothSkin = false, bVehicleSkin = false, bKillMsg = false, bDeadbox = false;
    CGunSkinSetting* gun;
    CClothSetting* cloth;
    CVehicleSetting* vehicle;

    CModSkinSetting() {
        gun = new CGunSkinSetting();
        cloth = new CClothSetting();
        vehicle = new CVehicleSetting();
    }

    ~CModSkinSetting() {
        delete gun;
        delete cloth;
        delete vehicle;
    }
};

static CModSkinSetting skin;

struct FSkinItem {
    std::string name;
    DWORD value;
    FSkinItem(std::string n, DWORD v) : name(std::move(n)), value(v) {}
    std::string ToStructString() const { return std::to_string(value); }
};

class CSkinsInfo {
public:
    DWORD* out = nullptr;
    bool bFirstInit = false;
    int current_index = 0;
    std::vector<FSkinItem> items;

    CSkinsInfo() = default;

    void Init(std::vector<FSkinItem> _items, DWORD* _out) {
        out = _out;
        items = std::move(_items);
        if (out && !items.empty()) {
            *out = items[0].value;
        }
    }

    DWORD At(int index) const { return (index < (int)items.size()) ? items[index].value : 0; }
    DWORD Get() const { return At(current_index); }
};

class SkinData {
public:
    CSkinsInfo m416, m16, akm, scarl, aug, m762, groza, ace32, honey, qbz,
               ump45, vector, tommy, uzi, pp19, kar98, m24, awm, amr, mk14,
               mini14, m249, dp28, mg3, pan, s12k, xm1014, dbs, cloth, hat,
               pant, shoe, parachute, glider, backpack1, helmet1, backpack2,
               helmet2, backpack3, helmet3, coupe, uaz, dacia, motor, buggy,
               mirado, knife, knife1;

    SkinData() {
        auto initSkin = [this](CSkinsInfo& skinInfo, DWORD* out, const std::vector<FSkinItem>& items) {
            skinInfo.Init(items, out);
        };

        // Clothes
        initSkin(cloth, &skin.cloth->SHIRT, {
            {"Default", 0}, {"Thánh Giáp Pharaoh Vàng (6 sao)", 1405628}, {"Thánh Giáp Pharaoh Vàng (7 Sao)", 1406469},
            {"Thánh Giáp Phong Linh Thiên Nữ (7 Sao)", 1407366}, {"Trang phục Miêu Nữ Công Nghệ", 1407286},
            {"Trang Phục Vệ Thần Tình Ái", 1407276}, {"Trang Phục Nữ Hoàng Giải Trí", 1407079},
            {"Trang Phục Thánh Nữ Huyền Ảo", 1407329}, {"Thánh Giáp Huyết Nha (6 Sao)", 1405870},
            {"Thánh Giáp Poseidon (6 Sao)", 1405983}, {"Thánh Giáp Băng Giá (6 Sao)", 1406152},
            {"Thánh Giáp Tinh Linh (6 Sao)", 1406311}, {"Thánh Giáp Cleopatra Vàng (6 Sao)", 1406475},
            {"Thánh Giáp Chúa Hề Bí Ẩn (6 Sao)", 1406641}, {"Thánh Giáp Huyết Thần Tai Ương (7 Sao)", 1406872},
            {"Thánh Giáp Thần Nữ Thủy Vực (7 Sao)", 1406971}, {"Trang Phục Đường Đến Địa Ngục", 1405623},
            {"Trang Phục Hỏa Thần Cổ Ngữ", 1407277}, {"Trang phục Huyền Thần", 1407275},
            {"Trang Phục Linh Hồn Xác Ướp", 1406891}, {"Trang Phục Xác Ướp Y Tá", 1400687},
            {"Zanmang Loopy Nghỉ Dưỡng", 1601048}, {"Thánh Giáp Hoa Linh Vĩnh Cửu (7 Sao)", 1407103},
            {"Trang Phục Thanh Hoa Xà", 1407161}, {"Trang phục Hỏa Diệm Ma Giáp", 1406398},
            {"Trang Phục Đô Đốc Huyễn Ảnh", 1407330}, {"Trang Phục Tiên Linh Lưu Ly", 1407225},
            {"Thánh Giáp Hỏa Linh Chí Tôn (7 sao)", 1407219}, {"Trang Phục Cô Dâu Quyến Rũ", 1405174},
            {"Trang Phục Diva Tím", 1407174}, {"Trang Phục Khủng Long Ephialtes", 1406897},
            {"Trang phục Apeachy", 1405208}, {"Trang phục Đội trưởng Ryan", 1405207},
            {"Áo Hoodie cá mập BAPE X PUBGM CAMO", 1404049}, {"Trang Phục Tử Thần Ma Xà", 1407387},
            {"Trang Phục Chúa Tể Băng Giá", 1407440}, {"Trang Phục Hồng Y Nữ Vương", 1407391},
            {"Trang Phục Ngôi Sao Tuyết Tinh Tú", 1407441}, {"Ngoại Trang Ngọc Lang Thiên Giới", 1407471},
            {"Lam Sư Đoạt Mệnh", 1407470}
        });

        initSkin(hat, &skin.cloth->HAT, {
            {"None", 0}, {"Mũ BAPE X PUBGM CAMO", 1402162}, {"Mũ Diva Tím", 1410585},
            {"Tóc 2 chùm", 40605012}, {"Tóc Cà Phê Muối", 40605014}, {"Mũ Đô Đốc Huyễn Ảnh", 1410686},
            {"Cài tóc cô dâu", 1402145}, {"Mũ Vệ Thần Tình Ái", 1410647}, {"Tiên Linh Lưu Ly", 12220054}
        });

        initSkin(pant, &skin.cloth->PANT, {{"None", 0}, {"Quần BAPE X PUBGM CAMO", 1404050}});

        initSkin(shoe, &skin.cloth->SHOE, {
            {"None", 0}, {"Giày BAPE X PUBGM CAMO", 1404051}, {"BAPE STA MID", 1400651}, {"Dép bơi", 1400371}
        });

        initSkin(parachute, &skin.cloth->PARACHUTE, {
            {"Dù Bùa Hộ Mệnh Pharaoh", 1401619}, {"Dù Huyết Nha", 1401621}, {"Dù LINE FRIENDS", 1401622},
            {"Dù Thần Horus", 1401615}, {"Dù Phượng Hoàng Adarna Ảo Diệu", 1401628}, {"Dù Lượn Lam Sư Tinh Hà", 4151092}
        });

        initSkin(glider, &skin.cloth->GLIDER, {
            {"Glider 1", 4151048}, {"Thiết bị bay Bằng Chíu", 4151010}, {"Tàu Lượn Chiến Thần Tình Yêu", 4151019}
        });

        auto initLevelItems = [&](CSkinsInfo& info, DWORD* out, int level) {
            std::vector<FSkinItem> items = {
                {"Ba lô Huyết Nha (Cấp " + std::to_string(level) + ")", 1501001220 + (level - 1) * 1000},
                {"Ba Lô Neon Huyền Bí (Cấp " + std::to_string(level) + ")", 1501001582 + (level - 1) * 1000},
                {"Ba lô cánh bướm (Cấp " + std::to_string(level) + ")", 1501001047 + (level - 1) * 1000},
                {"Ba lô Pharaoh (Cấp " + std::to_string(level) + ")", 1501001174 + (level - 1) * 1000},
                {"Ba Lô Mèo Điện Tử (Cấp " + std::to_string(level) + ")", 1501001496 + (level - 1) * 1000},
                {"Ba Lô Yêu Thỏ (Cấp " + std::to_string(level) + ")", 1501001495 + (level - 1) * 1000},
                {"Ba lô chú hề (Cấp " + std::to_string(level) + ")", 1501001051 + (level - 1) * 1000},
                {"Ba Lô Phong Linh (Cấp " + std::to_string(level) + ")", 1501001588 + (level - 1) * 1000},
                {"Ba lô Đội trưởng Ryan", 1501000057},
                {"Ba lô Godzilla (Cấp " + std::to_string(level) + ")", 1501001061 + (level - 1) * 1000},
                {"Ba lô BAPE X PUBGM CAMO (Cấp " + std::to_string(level) + ")", 1501001058 + (level - 1) * 1000},
                {"Ba lô cá mập (Cấp " + std::to_string(level) + ")", 1501001069 + (level - 1) * 1000},
                {"Ba Lô Kiếm Băng Tuyết (Cấp " + std::to_string(level) + ")", 1501001618 + (level - 1) * 1000},
                {"Ba Lô Khế Ước Thi Sĩ (Cấp " + std::to_string(level) + ")", 1501001628 + (level - 1) * 1000}
            };
            info.Init(items, out);
        };

        initLevelItems(backpack1, &skin.cloth->BACKPACK1, 1);
        initLevelItems(backpack2, &skin.cloth->BACKPACK2, 2);
        initLevelItems(backpack3, &skin.cloth->BACKPACK3, 3);

        auto initHelmet = [&](CSkinsInfo& info, DWORD* out, int level) {
            info.Init({{"Mũ sắt băng tuyết (Cấp " + std::to_string(level) + ")", 1502001023 + (level - 1) * 1000},
                       {"Mũ kỵ sĩ hỏa ngục (Cấp " + std::to_string(level) + ")", 1502001014 + (level - 1) * 1000}}, out);
        };

        initHelmet(helmet1, &skin.cloth->HELMET1, 1);
        initHelmet(helmet2, &skin.cloth->HELMET2, 2);
        initHelmet(helmet3, &skin.cloth->HELMET3, 3);

        // Vehicles
        initSkin(uaz, &skin.vehicle->UAZ, {
            {"None", 0}, {"Bentley Betayga Azure (Mưa Hoa)", 1908094}, {"Bentley Betayga Azure (Đêm Yên Tĩnh)", 1908095},
            {"Xe UAZ Siêu Thú Godzilla (Cấp 3)", 1908032}, {"Xe UAZ Bí Ngô Ma Quái (Cấp 3)", 1908036},
            {"Lamborghini Urus Pink", 1908066}, {"Lamborghini Urus Giallo Inti", 1908067},
            {"Maserati Levante Blu Emozione", 1908075}, {"Maserati Luce Arancione", 1908076},
            {"Maserati Levante Neon Urbano", 1908077}, {"Maserati Levante Firmamento", 1908078},
            {"Aston Martin DBX707 (Neon Purple)", 1908084}, {"Aston Martin DBX707 (Quasar Blue)", 1908085},
            {"Dodge Hornet - Scarlet Sting", 1908086}, {"Dodge Hornet GLH Concept - Redline", 1908088},
            {"Dodge Hornet - Sunburst", 1908089}
        });

        initSkin(motor, &skin.vehicle->MOTOR, {
            {"None", 0}, {"Xe Mô Tô Bóng Ma (Cấp 7)", 1901047}, {"Xe máy Hổ gầm gừ (Cấp 3)", 1901027},
            {"MWT-9", 1901050}, {"MWT-9 (Vàng)", 1901052}, {"DUCATI Panigale V4S", 1901073},
            {"Ducati Panigale V4S Black Phantom", 1901074}, {"Ducati Panigale V4S Crimson Storm", 1901075},
            {"Ducati Panigale V4S Swift Mirage", 1901076}
        });

        initSkin(mirado, &skin.vehicle->MIRADO, {
            {"None", 0}, {"VW Beetle Convertible Mới (Hồng)", 1915010}, {"VW Beetle Convertible Mới (Quái Vật)", 1915012},
            {"Aston Martin DBS Volante (Deep Cosmos)", 1915005}, {"Aston Martin DBS Volante (Celestial Pink)", 1915006},
            {"Aston Martin DBS Volante (Black-Bronze Satin)", 1915007},
            {"Bentley Continental GTC Mulliner (Mộng Cảnh Lung Linh)", 1915009}
        });

        initSkin(dacia, &skin.vehicle->DACIA, {
            {"None", 0}, {"Bentley Flying Spur Mulliner (Tinh Vân Xanh)", 1903200},
            {"Bentley Flying Spur Mulliner (Dòng Chảy Vịnh Hẹp)", 1903201}, {"Koenigsegg Gemera (Cầu Vồng)", 1903075},
            {"Tesla Roadster (Kim Cương)", 1903071}, {"Tesla Roadster (Pha Lê Tím)", 1903072},
            {"Tesla Roadster (Xanh Biển Cả)", 1903073}, {"Koenigsegg Gemera (Xám Bạc)", 1903074},
            {"Koenigsegg Gemera (Bình Minh)", 1903076}
        });

        initSkin(buggy, &skin.vehicle->BUGGY, {
            {"None", 0}, {"Xe Đua Đội McLaren F1 (Điện Tử)", 1907054}, {"Xe Đua Đội McLaren F1", 1907058},
            {"Xe Đua Đội McLaren F1 (Chiến Thắng)", 1907059}
        });

        initSkin(coupe, &skin.vehicle->COUPE, {
            {"None", 0}, {"McLaren P1 (Trời Sao)", 1961147}, {"McLaren P1 (Hồng Rực Rỡ)", 1961148},
            {"McLaren P1 (Vàng Núi Lửa)", 1961149}, {"Bentley Betayga Azure (Vương Quốc Huyền Ảo)", 1961139},
            {"Lamborghini Invencible Rosso Efesto", 1961144}, {"Lamborghini Invencible Nebula Drift", 1961145},
            {"Bentley Batur (Holoprism)", 1961137}, {"Bentley Batur (Solar Pulse)", 1961138},
            {"Bentley Batur (Bonneville Pearlescent Silver)", 1961139}, {"Warp Green", 1961033},
            {"Warp Dawn", 1961034}, {"Warp Universe", 1961035}, {"McLaren 570S (Đen)", 1961007},
            {"McLaren 570S (Trắng)", 1961010}, {"McLaren 570S (Hồng)", 1961012}, {"McLaren 570S (Vàng Trắng)", 1961013},
            {"McLaren 570S (Vàng Đen)", 1961014}, {"McLaren 570S (Ánh Kim)", 1961015},
            {"Koenigsegg Jesko (Xám Bạc)", 1961016}, {"Koenigsegg Jesko (Cầu Vồng)", 1961017},
            {"Koenigsegg Jesko (Bình Minh)", 1961018}, {"Lamborghini Aventador SVJ Verde Alceo", 1961020},
            {"Lamborghini Centenario Galassia", 1961021}, {"Lamborghini Aventador SVJ Blue", 1961024},
            {"Lamborghini Centenario Carbon Fiber", 1961025}, {"Koenigsegg One:1 Gilt", 1961029},
            {"Koenigsegg One:1 Cyber Nebula", 1961030}, {"Koenigsegg One:1 Jade", 1961031},
            {"Bugatti Veyron 16.4 (Sắc Màu)", 1961041}, {"Bugatti Veyron 16.4 (Vàng)", 1961042},
            {"Bugatti La Voiture Noire", 1961044}, {"Aston Martin Valkyrie (Luminous Diamond)", 1961048},
            {"Dodge Challenger SRT Hellcat Jailbreak - Hellfire", 1961050}, {"Pagani Zonda R (Tricolore Carbon)", 1961051}
        });

        // Guns
        initSkin(m16, &skin.gun->M16A4, {{"Lõi Skeletal - M16A4 (Cấp 7)", 1101002081}});
        initSkin(m416, &skin.gun->M416, {
            {"Băng giá - M416 (Cấp 7)", 1101004046}, {"Lam Sư Đoạt Mệnh - M416 (Cấp 8)", 1101004236},
            {"Phong Ấn U Minh - M416 (Cấp 8)", 1101004226}, {"Chú hề - M416 (Cấp 7)", 1101004062},
            {"Bò Sát Gầm Gừ - M416 (Cấp 7)", 1101004086}, {"Hoàng Gia Lộng Lẫy - M416 (Cấp 8)", 1101004163},
            {"Bạch Lân Nhả Ngọc - M416 (Cấp 8)", 1101004201}, {"Thủy Triều Dậy Sóng - M416 (Cấp 8)", 1101004209},
            {"Ma Ảnh - M416 (Cấp 8)", 1101004218}
        });
        initSkin(akm, &skin.gun->AKM, {
            {"Đô Đốc Hải Long Tinh - AKM (Cấp 8)", 1101001213}, {"Thỏ Tinh Nghịch - AKM (Cấp 7)", 1101001231},
            {"Ngày Phán Quyết - AKM (Cấp 8)", 1101001242}, {"Thánh Quang (Lông Vũ Hoàng Kim) - AKM (Lv7)", 1101001256},
            {"Thánh Quang (Trăng Thần) - AKM (Lv7)", 1101001249}
        });
        initSkin(scarl, &skin.gun->SCARL, {
            {"Ma Vương Huyết Hồn - SCAR-L (Cấp 8)", 1101003167}, {"Cái Ôm Của Chú Hề - SCAR-L (Cấp 7)", 1101003181},
            {"Thánh Nữ Huyền Ảo - SCAR-L (Cấp 7)", 1101003195}, {"Vương Quốc Huyền Ảo -SCAR-L (Cấp 7)", 1101003208}
        });
        initSkin(aug, &skin.gun->AUG, {{"Tinh Linh Băng Giá - AUG (Cấp 8)", 1101006062}, {"Hỏa Ca - AUG (Cấp 7)", 1101006075}});
        initSkin(m762, &skin.gun->M762, {
            {"Huyết Rồng - M762 (Cấp 7)", 1101008126}, {"Tiên Linh Lưu Ly - M762 (Cấp 7)", 1101008136},
            {"Bạch Cốt U Minh - M762 (Cấp 8)", 1101008146}, {"Khung Xương - M762 (Cấp 8)", 1101008154}
        });
        initSkin(groza, &skin.gun->GROZA, {{"Lửa U Minh - Groza (Cấp 7)", 1101005052}, {"Di Tích Thượng Cổ - Groza (Cấp 5)", 1101005090}});
        initSkin(honey, &skin.gun->HONEY, {{"Sắc Màu Huyền Ảo - Honey Badger (Cấp 5)", 1101012009}});
        initSkin(ace32, &skin.gun->ACE32, {
            {"Kamehameha - ACE32 (Cấp 7)", 1101102007}, {"Ngọc Bích - ACE32 (Cấp 7)", 1101102017},
            {"Thủy Quái - ACE32 (Cấp 8)", 1101102025}
        });
        initSkin(qbz, &skin.gun->QBZ, {
            {"Công Chúa Hắc Ám - QBZ (Cấp 7)", 1101007046}, {"Hoa Kiếm Chí Mạng - QBZ (Cấp 7)", 1101007062},
            {"Thiên Mệnh - QBZ (Cấp 7)", 1101007071}
        });

        // SMG
        initSkin(ump45, &skin.gun->UMP45, {{"Băng Giá - UMP45 (Cấp 7)", 1102002136}});
        initSkin(uzi, &skin.gun->UZI, {
            {"Cam Tươi Mát - UZI (Cấp 5)", 1102001103}, {"Phong Ấn - UZI (Cấp 3)", 1102001112},
            {"Savagery - UZI (Cấp 5)", 1102001998}, {"Máy Ép Trái Cây - UZI (Cấp 5)", 1102001102},
            {"Băng Giá - UZI (Cấp 8)", 1102001120}
        });
        initSkin(vector, &skin.gun->VECTOR, {{"Cánh Rồng - Vector (Cấp 7)", 1102003080}});
        initSkin(pp19, &skin.gun->PP19, {{"Lân Sư - PP-19 Bizon (Cấp 5)", 1102005057}});
        initSkin(tommy, &skin.gun->TOMMY, {{"Kẹo ngọt - Thompson (Cấp 5)", 1102004018}});

        // Sniper
        initSkin(kar98, &skin.gun->KAR98, {{"Điện Cực Tím - Kar98K (Cấp 7)", 1103001179}, {"Hồng Hỏa Diệm - Kar98 (Cấp 7)", 1103001191}});
        initSkin(m24, &skin.gun->M24, {{"Nhịp Điệu Hoàn Mỹ - M24 (Cấp 7)", 1103002087}, {"Công Nghệ Cao - M24 (Cấp 5)", 1103002094}});
        initSkin(awm, &skin.gun->AWM, {{"Thanh Hoa Xà - AWM (Cấp 7)", 1103003087}});
        initSkin(amr, &skin.gun->AMR, {
            {"Khủng Long Ephialtes - AMR (Cấp 8)", 1103012010}, {"Hỏa Thần - AMR (Cấp 7)", 1103012019},
            {"Tinh Thể Onyx - AMR (Cấp 5)", 1103012024}, {"Vô Âm Ly Biệt - AMR (Cấp 7)", 1103012031}
        });
        initSkin(mk14, &skin.gun->MK14, {{"Vương Quốc Rồng - Mk14 (Cấp 8)", 1103007028}});
        initSkin(mini14, &skin.gun->MINI14, {{"Sông Băng - Mini14 (Cấp 7)", 1103006030}});

        // LMG
        initSkin(m249, &skin.gun->M249, {{"Nữ Đế Ánh Sáng - M249 (Cấp 7)", 1105001048}, {"Graffiti Đường Phố - M249 (Cấp 5)", 1105001062}});
        initSkin(dp28, &skin.gun->DP28, {
            {"Rồng Thần Shenron - DP-28 (Cấp 5)", 1105002063}, {"Chiến Sĩ Thần Giáp - DP-28 (Cấp 5)", 1105002071},
            {"Mèo Số Hóa - DP-28 (Cấp 5)", 1105002076}
        });
        initSkin(mg3, &skin.gun->MG3, {{"Thiên Khung - MG3 (Cấp 5)", 1105010008}, {"Chiến Thần Bầu Trời - MG3 (Cấp 7)", 1105010019}});
        initSkin(pan, &skin.gun->PAN, {
            {"Gà Rán - Chảo (Cấp 3)", 1108004356}, {"Chảo - Đội trưởng Ryan", 1108004060},
            {"Chảo - Apeachy", 1108004061}, {"Chảo - BAPE X PUBGM CAMO", 1108004062}
        });
        initSkin(knife, &skin.gun->KNIFE, {
            {"Săn Rồng - Dao (Cấp 3)", 1108001057}, {"Doản Kiếm Yor SPY×FAMILY (Lv3)", 1108001064},
            {"Ki Sword (Cấp 3)", 1108001069}
        });
        initSkin(knife1, &skin.gun->KNIFE1, {{"Rồng Băng Giá - Dao Găm (Cấp 3)", 1108005050}});

        // Shotgun
        initSkin(s12k, &skin.gun->S12K, {{"Chiến Ưng Vàng - S12K", 1104003027}, {"Kích Hoạt Nguyên Tử - S12K (Cấp 5)", 1104003037}});
        initSkin(dbs, &skin.gun->DBS, {{"Báo Sắc Màu - DBS (Cấp 3)", 1104004024}, {"Chiến Giáp Quái Thú - DBS (Cấp 5)", 1104004035}});
        initSkin(xm1014, &skin.gun->XM1014, {{"Lễ Hội Chết Chóc - M1014", 1104101001}});
    }
};

static SkinData skindata;

// ── end skin_data.h ──────────────────────────────────────────────────────────

extern "C" void ImGui_SetTouchEvent(int action, float x, float y);

bool Thundertest = false;
float screenSizeX = 0;
float screenSizeY = 0;

#define GNames_Offset 0x85dbcec//名称
#define GUObject_Offset 0xea31560//结构
#define GEngine_Offset 0xecf15c0 //引擎对象
#define GetActorArray_Offset 0xa34a0d0//AActor数组
#define GNativeAndroidApp_Offset 0xe775f98//应用程序
#define CanvasMap_Offset 0xea34230//画布地图
#define KillMessage_Offset 0x5c5b268//击杀提示
#define ProcessEvent_Offset 0x884e068 //子(虚/副)
#define PostRer_Offset 0xa253214//后期偏移
#define Actors_Offset 0xa0
#define UpdateVolley_Offset 0x6BD8D84
//#define LaunchBP Offsets 0x7221730


#define IM_PI 3.14159265358979323846f
#define RAD2DEG(x) ((float)(x) * (float)(180.f / IM_PI))
#define DEG2RAD(x) ((float)(x) * (float)(IM_PI / 180.f))

#define DEG2RADD(x) ((float)(x) * (float)(IM_PI / 360.f))


#ifndef DWORD
#define _BYTE  uint8_t
#define _WORD  uint16_t
#define _DWORD uint32_t
#define _QWORD uint64_t
#define DWORD  uint32_t
#endif

#define HOOK_LIB(lib, addr, hook, orig)
#define OBFUSCATE
#define libanort ("libanort.so")
#define libUE4 ("libUE4.so")
#define libgcloud ("libgcloud.so")
#define ARM64_SYSREG uint64_t
#undef libanogs
#define libanogs "libanogs.so"
#define findLibrary
#undef isLibraryLoaded
#define isLibraryLoaded
#define xor_str


#define PATCH_LIB
#define HOOK_LIB_NO_ORIG(lib, offset, func)
#define HOOK_LIB_THUMB

ImVec4 buttonColor = ImVec4(0.745f, 0.151f, 0.151f, 1.0f);
ImVec4 buttonStyle = ImVec4(buttonColor.x, buttonColor.y, buttonColor.z, buttonColor.w);
  bool WriteAddr(void *addr, void *buffer, size_t length) {
unsigned long page_size = sysconf(_SC_PAGESIZE);
unsigned long size = page_size * sizeof(uintptr_t);
return mprotect((void *) ((uintptr_t) addr - ((uintptr_t) addr % page_size) - page_size), (size_t) size, PROT_EXEC | PROT_READ | PROT_WRITE) == 0 && memcpy(addr, buffer, length) != 0;
}

static std::unordered_map<std::string, bool> isDumped;
std::unordered_set<int> loggedIDs;

template<typename T>
T Read(uintptr_t address)
{
if (address == 0)  // Null check
return T{};

try {
return *reinterpret_cast<T*>(address);
} catch (...) {
return T{};
}} 



template<typename T>
void Write(uintptr_t addr, T value) {
WriteAddr((void *) addr, &value, sizeof(T));
}

int Write_Float(long int addr, float value) {
Tools::WriteAddr((void *) (addr), (void *) &value, 4);
return 0;
}


void pvm2(uintptr_t address, void* buffer, size_t size)
{
if (address == 0 || buffer == nullptr || size == 0)
return;

memcpy(reinterpret_cast<void*>(address), buffer, size);
}




json items_data;
std::string g_Token, g_Auth;
std::string errMsg;
static std::string EXP = "";
static std::string mod_status = " ";

bool bValid = false;
uintptr_t UE4;
uintptr_t g_UE4;
uintptr_t g_Anogs;
android_app *g_App = 0;
ImFont* logo;
ImFont *pRegularFont;
ImFont* FlithPapa = nullptr;
ASTExtraPlayerCharacter *g_LocalPlayer = 0;
ASTExtraPlayerController *g_LocalController = 0;
bool firestip;
bool firetur;
bool Bypass = true;
bool anticrack = true;
bool otofere;
bool HIDEESP = false;
bool initImGui = false;
static bool g_SkinOpen = false;  // Skin window state

// ── Floating icon drag state ─────────────────────────────────────
static float  g_IconX        = -1.0f;
static float  g_IconY        = -1.0f;
static bool   g_IconDragging = false;
static float  g_IconDragOffX = 0.0f;
static float  g_IconDragOffY = 0.0f;
static float  g_IconPulse    = 0.0f;
static float  g_IconScale    = 1.0f;
// ── Sidebar levitation animation ──────────────────────────────────
static float  g_SideFloat    = 0.0f;   // sinf phase for floating effect
static float  g_TabFloat[4]  = {0,0,0,0}; // per-tab hover float
int screenWidth = -1, glWidth, screenHeight = -1, glHeight;
float density = -1;
 

UWorld *GEWorld;
int GWorldNum = 0;
TUObjectArray gobjects;
UWorld *GetWorld()
{
if(GWorldNum == 0) {
gobjects = UObject::GUObjectArray->ObjObjects;
for (int i=0; i< gobjects.Num(); i++)
if (auto obj = gobjects.GetByIndex(i)) {
if(obj->IsA(UEngine::StaticClass())) {
auto GEngine = (UEngine *) obj;
if(GEngine) {
auto ViewPort = GEngine->GameViewport;
if (ViewPort)
{
GEWorld = ViewPort->World;
GWorldNum = i;
return ViewPort->World;
}}}}
  }else {
auto GEngine = (UEngine *) (gobjects.GetByIndex(GWorldNum));
if(GEngine) {
auto ViewPort = GEngine->GameViewport;
if(ViewPort) {
GEWorld = ViewPort->World;
return ViewPort->World;
}}}
return 0;
}

std::vector<AActor *> GetActors()
{
auto World = GetWorld();
if (!World)
return std::vector<AActor *>();
auto PersistentLevel = World->PersistentLevel;
if (!PersistentLevel)
return std::vector<AActor *>();
auto Actors = *(TArray<AActor *> *)((uintptr_t)PersistentLevel + Actors_Offset);
std::vector<AActor *> actors;
for (int i = 0; i < Actors.Num(); i++)
{
auto Actor = Actors[i];
if (Actor)
{
actors.push_back(Actor);
}}
return actors;
}

TNameEntryArray *GetGNames()
{
return ((TNameEntryArray * (*)())(UE4 + GNames_Offset))();
}


template <class T>
void GetAllActors(std::vector<T *> &Actors)
{
UGameplayStatics *gGameplayStatics = (UGameplayStatics *)gGameplayStatics->StaticClass();
auto GWorld = GetWorld();
if (GWorld)
{
TArray<AActor *> Actors2;
gGameplayStatics->GetAllActorsOfClass((UObject *)GWorld, T::StaticClass(), &Actors2);
for (int i = 0; i < Actors2.Num(); i++)
{
Actors.push_back((T *)Actors2[i]);
}}}
static UGameViewportClient *GameViewport = 0;

UGameViewportClient *GetGameViewport() {
while (!GameViewport) {
GameViewport = UObject::FindObject<UGameViewportClient>("GameViewportClient Transient.UAEGameEngine_1.GameViewportClient_1");
sleep(1);}
if (GameViewport) {
return GameViewport;}
return 0;
}

std::string getObjectPath(UObject *Object) {
std::string s;
for (auto super = Object->ClassPrivate; super; super = (UClass *) super->SuperStruct) {
if (!s.empty())
s += ".";
s += super->NamePrivate.GetName();
}
return s;
}


enum class EAimBy {
    FOV = 0,
    Distance = 1
};

enum class EAimTarget {
    Head = 0,
    Neck = 1,
    Chest = 2,
    Pelvis = 3
};

enum class EAimTrigger {
    None = 0,
    Shooting = 1,
    Scoping = 2,
    Both = 3,
    Any = 4
};
std::map<int, bool> Items;
std::map<int, float *> ItemColors;
struct sConfig {

bool Unlock120FPS;
bool Nofog;
bool Bypass;
bool Speed;
float Skill;
float Skill1;
float Skill3;
float Skill4;
float Skill2;
float Line;
float Skeleton;
float Loot;
struct sESPMenu {
bool Line;
bool Box;
bool Skeleton;
bool Health;
bool Triangle;
bool ShowKnockedHealth;
bool Name;
bool Distance;
bool WideView;
bool TeamID;
bool TargetLine;
bool Dbox;
bool Radar;
bool ALEART;
bool Instant;
bool Offsc;
bool Genn;
bool NoBot;
bool Loot;
bool LootBox;
bool LootBoxItems;
bool Weapon;
bool AirDrop;
};
sESPMenu ESPMenu;
struct sHighRisk {
bool NoShake;
bool NoRecoil;
bool Instant;
bool SmallCrossHair;
float FastShoot;
bool Ghost;
bool DEVIL;
bool Para;
bool HitEffect;
};
sHighRisk HighRisk{0};
struct sVehicleESP {
bool ShowVehicle;
bool ShowDistance;
};
sVehicleESP VehicleESP{0};
 struct sAimBot
{
  bool Enable = false;
  bool Fov = false;
  int AimBy = 0;
  int Target = 0;
  int Trigger = 0;
  bool Pred = false;
  bool VisCheck = false;
  bool ReCo = false;
  bool IgnoreKnocked = false;
  bool IgnoreBot = false;
  bool VisCheckLine = false;
  float Cross = 100.0f;
  float FOV = 100.0f;
  float Smooth = 2.0f;
  float AimDist = 200.0f;
  float Recc = 4.0f;
  float Meter = 200.0f;
  bool RecoilComparison;
};
sAimBot AimBot{0};

struct sSilentAim {
bool Enable = false;
bool VisibleCheck = true;
bool IgnoreKnocked = false;
bool IgnoreBot = false;
bool VehiclePrediction = true;
bool FakeDamage;
float FOV = 100.0f;
float MaxDistance = 150.0f;
int Trigger = 3;
int TargetBone = 0;
};
sSilentAim SilentAim{0};

struct sOTHER {
bool FPS;
};
sOTHER OTHER{0};
struct sMemory {
bool FakeName = false;
};
sMemory Memory{};
struct sRagebot {
bool Enable = false;
int Aimtype = 0;
int Trigger = 0;
};
sRagebot Ragebot{};
struct sColorsESP {
float *Text;
float *Menucolour;
float *Line;
float *Box;
float *Color;
float *Boxbot;
float *Name;
float *Distance;
float *Skeleton;
float *Skeletonbot;
float *Skeletonnon;
float *SkeletonVisible;
float *BotNn;
float *BotNv;
float *PotNn;
float *PotNv;
float *Fov;
float *Fova;
float *nonbot;
float *Linebot;
float *Count;
float *Vehicle;
};
sColorsESP ColorsESP{0};
};

sConfig Config{0};

// ── Language system ──────────────────────────────────────────────────────────
// false = English, true = Russian
static bool g_LangRU = false;

// Inline translator: T(en, ru)
static inline const char* T(const char* en, const char* ru) {
    return g_LangRU ? ru : en;
}

// ── Config save/load path ────────────────────────────────────────────────────
static const char* CFG_PATH = "/storage/emulated/0/Android/data/com.pubg.imobile/files/mtr_cfg.json";

static const char* CFG_PATHS[] = {
    "/storage/emulated/0/Android/data/com.pubg.imobile/files/mtr_cfg.json",
    "/storage/emulated/0/Android/data/com.tencent.ig/files/mtr_cfg.json",
    "/storage/emulated/0/Android/data/com.pubg.krmobile/files/mtr_cfg.json",
    "/storage/emulated/0/Android/data/com.rekoo.pubgm/files/mtr_cfg.json",
    "/storage/emulated/0/Android/data/com.vng.pubgmobile/files/mtr_cfg.json",
};
static const int CFG_PATHS_COUNT = 5;

static void SaveConfig() {
    json j;
    // AimBot
    j["AimBot"]["Enable"]        = Config.AimBot.Enable;
    j["AimBot"]["AimBy"]         = Config.AimBot.AimBy;
    j["AimBot"]["Target"]        = Config.AimBot.Target;
    j["AimBot"]["Trigger"]       = Config.AimBot.Trigger;
    j["AimBot"]["Pred"]          = Config.AimBot.Pred;
    j["AimBot"]["VisCheck"]      = Config.AimBot.VisCheck;
    j["AimBot"]["IgnoreKnocked"] = Config.AimBot.IgnoreKnocked;
    j["AimBot"]["IgnoreBot"]     = Config.AimBot.IgnoreBot;
    j["AimBot"]["FOV"]           = Config.AimBot.FOV;
    j["AimBot"]["Smooth"]        = Config.AimBot.Smooth;
    j["AimBot"]["AimDist"]       = Config.AimBot.AimDist;
    j["AimBot"]["Recc"]          = Config.AimBot.Recc;
    // SilentAim
    j["SilentAim"]["Enable"]            = Config.SilentAim.Enable;
    j["SilentAim"]["VisibleCheck"]      = Config.SilentAim.VisibleCheck;
    j["SilentAim"]["IgnoreKnocked"]     = Config.SilentAim.IgnoreKnocked;
    j["SilentAim"]["IgnoreBot"]         = Config.SilentAim.IgnoreBot;
    j["SilentAim"]["VehiclePrediction"] = Config.SilentAim.VehiclePrediction;
    j["SilentAim"]["FakeDamage"]        = Config.SilentAim.FakeDamage;
    j["SilentAim"]["FOV"]               = Config.SilentAim.FOV;
    j["SilentAim"]["MaxDistance"]       = Config.SilentAim.MaxDistance;
    j["SilentAim"]["Trigger"]           = Config.SilentAim.Trigger;
    j["SilentAim"]["TargetBone"]        = Config.SilentAim.TargetBone;
    // ESP
    j["ESP"]["Line"]          = Config.ESPMenu.Line;
    j["ESP"]["Box"]           = Config.ESPMenu.Box;
    j["ESP"]["Skeleton"]      = Config.ESPMenu.Skeleton;
    j["ESP"]["Health"]        = Config.ESPMenu.Health;
    j["ESP"]["Triangle"]      = Config.ESPMenu.Triangle;
    j["ESP"]["Name"]          = Config.ESPMenu.Name;
    j["ESP"]["Distance"]      = Config.ESPMenu.Distance;
    j["ESP"]["WideView"]      = Config.ESPMenu.WideView;
    j["ESP"]["TeamID"]        = Config.ESPMenu.TeamID;
    j["ESP"]["TargetLine"]    = Config.ESPMenu.TargetLine;
    j["ESP"]["Radar"]         = Config.ESPMenu.Radar;
    j["ESP"]["Loot"]          = Config.ESPMenu.Loot;
    j["ESP"]["AirDrop"]       = Config.ESPMenu.AirDrop;
    j["ESP"]["Weapon"]        = Config.ESPMenu.Weapon;
    j["ESP"]["NoBot"]         = Config.ESPMenu.NoBot;
    // HighRisk
    j["HighRisk"]["NoShake"]        = Config.HighRisk.NoShake;
    j["HighRisk"]["NoRecoil"]       = Config.HighRisk.NoRecoil;
    j["HighRisk"]["Instant"]        = Config.HighRisk.Instant;
    j["HighRisk"]["SmallCrossHair"] = Config.HighRisk.SmallCrossHair;
    j["HighRisk"]["FastShoot"]      = Config.HighRisk.FastShoot;
    j["HighRisk"]["Ghost"]          = Config.HighRisk.Ghost;
    j["HighRisk"]["HitEffect"]      = Config.HighRisk.HitEffect;
    // Settings
    j["Settings"]["HIDEESP"] = HIDEESP;
    j["Settings"]["LangRU"]  = g_LangRU;

    std::string data = j.dump(4);
    for (int i = 0; i < CFG_PATHS_COUNT; i++) {
        std::ofstream f(CFG_PATHS[i]);
        if (f.is_open()) {
            f << data;
            f.close();
        }
    }
}

static bool LoadConfig() {
    std::ifstream f;
    for (int i = 0; i < CFG_PATHS_COUNT; i++) {
        f.open(CFG_PATHS[i]);
        if (f.is_open()) break;
    }
    if (!f.is_open()) return false;
    try {
        json j;
        f >> j;
        // AimBot
        if (j.contains("AimBot")) {
            auto& a = j["AimBot"];
            if (a.contains("Enable"))        Config.AimBot.Enable        = a["Enable"];
            if (a.contains("AimBy"))         Config.AimBot.AimBy         = a["AimBy"];
            if (a.contains("Target"))        Config.AimBot.Target        = a["Target"];
            if (a.contains("Trigger"))       Config.AimBot.Trigger       = a["Trigger"];
            if (a.contains("Pred"))          Config.AimBot.Pred          = a["Pred"];
            if (a.contains("IgnoreKnocked")) Config.AimBot.IgnoreKnocked = a["IgnoreKnocked"];
            if (a.contains("IgnoreBot"))     Config.AimBot.IgnoreBot     = a["IgnoreBot"];
            if (a.contains("FOV"))           Config.AimBot.FOV           = a["FOV"];
            if (a.contains("Smooth"))        Config.AimBot.Smooth        = a["Smooth"];
            if (a.contains("AimDist"))       Config.AimBot.AimDist       = a["AimDist"];
            if (a.contains("Recc"))          Config.AimBot.Recc          = a["Recc"];
        }
        // SilentAim
        if (j.contains("SilentAim")) {
            auto& s = j["SilentAim"];
            if (s.contains("Enable"))            Config.SilentAim.Enable            = s["Enable"];
            if (s.contains("VisibleCheck"))      Config.SilentAim.VisibleCheck      = s["VisibleCheck"];
            if (s.contains("IgnoreKnocked"))     Config.SilentAim.IgnoreKnocked     = s["IgnoreKnocked"];
            if (s.contains("IgnoreBot"))         Config.SilentAim.IgnoreBot         = s["IgnoreBot"];
            if (s.contains("VehiclePrediction")) Config.SilentAim.VehiclePrediction = s["VehiclePrediction"];
            if (s.contains("FakeDamage"))        Config.SilentAim.FakeDamage        = s["FakeDamage"];
            if (s.contains("FOV"))               Config.SilentAim.FOV               = s["FOV"];
            if (s.contains("MaxDistance"))       Config.SilentAim.MaxDistance       = s["MaxDistance"];
            if (s.contains("Trigger"))           Config.SilentAim.Trigger           = s["Trigger"];
            if (s.contains("TargetBone"))        Config.SilentAim.TargetBone        = s["TargetBone"];
        }
        // ESP
        if (j.contains("ESP")) {
            auto& e = j["ESP"];
            if (e.contains("Line"))       Config.ESPMenu.Line       = e["Line"];
            if (e.contains("Box"))        Config.ESPMenu.Box        = e["Box"];
            if (e.contains("Skeleton"))   Config.ESPMenu.Skeleton   = e["Skeleton"];
            if (e.contains("Health"))     Config.ESPMenu.Health     = e["Health"];
            if (e.contains("Triangle"))   Config.ESPMenu.Triangle   = e["Triangle"];
            if (e.contains("Name"))       Config.ESPMenu.Name       = e["Name"];
            if (e.contains("Distance"))   Config.ESPMenu.Distance   = e["Distance"];
            if (e.contains("WideView"))   Config.ESPMenu.WideView   = e["WideView"];
            if (e.contains("TeamID"))     Config.ESPMenu.TeamID     = e["TeamID"];
            if (e.contains("TargetLine")) Config.ESPMenu.TargetLine = e["TargetLine"];
            if (e.contains("Radar"))      Config.ESPMenu.Radar      = e["Radar"];
            if (e.contains("Loot"))       Config.ESPMenu.Loot       = e["Loot"];
            if (e.contains("AirDrop"))    Config.ESPMenu.AirDrop    = e["AirDrop"];
            if (e.contains("Weapon"))     Config.ESPMenu.Weapon     = e["Weapon"];
            if (e.contains("NoBot"))      Config.ESPMenu.NoBot      = e["NoBot"];
        }
        // HighRisk
        if (j.contains("HighRisk")) {
            auto& h = j["HighRisk"];
            if (h.contains("NoShake"))        Config.HighRisk.NoShake        = h["NoShake"];
            if (h.contains("NoRecoil"))       Config.HighRisk.NoRecoil       = h["NoRecoil"];
            if (h.contains("Instant"))        Config.HighRisk.Instant        = h["Instant"];
            if (h.contains("SmallCrossHair")) Config.HighRisk.SmallCrossHair = h["SmallCrossHair"];
            if (h.contains("FastShoot"))      Config.HighRisk.FastShoot      = h["FastShoot"];
            if (h.contains("Ghost"))          Config.HighRisk.Ghost          = h["Ghost"];
            if (h.contains("HitEffect"))      Config.HighRisk.HitEffect      = h["HitEffect"];
        }
        // Settings
        if (j.contains("Settings")) {
            auto& st = j["Settings"];
            if (st.contains("HIDEESP")) HIDEESP   = st["HIDEESP"];
            if (st.contains("LangRU"))  g_LangRU  = st["LangRU"];
        }
        return true;
    } catch (...) { return false; }
}

// ── Config status message ────────────────────────────────────────────────────
static std::string g_CfgMsg   = "";
static float       g_CfgMsgT  = 0.0f;   // seconds remaining to show message

#define CREATE_COLOR(r, g, b, a) new float[4] {(float)r, (float)g, (float)b, (float)a};
struct sRegion {
uintptr_t start, end;
};

std::vector<sRegion> trapRegions;

bool isObjectInvalid(UObject *obj) {
if (!Tools::IsPtrValid(obj)) {
return true;
}

if (!Tools::IsPtrValid(obj->ClassPrivate)) {
return true;
}

if (obj->InternalIndex <= 0) {
return true;
}

if (obj->NamePrivate.ComparisonIndex <= 0) {
return true;
}

if ((uintptr_t)(obj) % sizeof(uintptr_t) != 0x0 && (uintptr_t)(obj) % sizeof(uintptr_t) != 0x4) {
return true;
}

if (std::any_of(trapRegions.begin(), trapRegions.end(), [obj](sRegion region) { return ((uintptr_t) obj) >= region.start && ((uintptr_t) obj) <= region.end; }) ||
std::any_of(trapRegions.begin(), trapRegions.end(), [obj](sRegion region) { return ((uintptr_t) obj->ClassPrivate) >= region.start && ((uintptr_t) obj->ClassPrivate) <= region.end; })) {
return true;
}

return false;
}


int32_t ToColor(float *col) {
return ImGui::ColorConvertFloat4ToU32(*(ImVec4 *) (col));
}

struct Matrix
{
float m[4][4];
};

struct D3DMatrix
{
float _11, _12, _13, _14;
float _21, _22, _23, _24;
float _31, _32, _33, _34;
float _41, _42, _43, _44;
};

D3DMatrix QuatToMatrix(const FQuat &quat)
{
D3DMatrix mat;

float magnitude = std::sqrt(quat.X * quat.X + quat.Y * quat.Y + quat.Z * quat.Z + quat.W * quat.W);
float qx = quat.X / magnitude;
float qy = quat.Y / magnitude;
float qz = quat.Z / magnitude;
float qw = quat.W / magnitude;

float xx = qx * qx;
float xy = qx * qy;
float xz = qx * qz;
float xw = qx * qw;

float yy = qy * qy;
float yz = qy * qz;
float yw = qy * qw;

float zz = qz * qz;
float zw = qz * qw;

mat._11 = 1.0f - 2.0f * (yy + zz);
mat._12 = 2.0f * (xy - zw);
mat._13 = 2.0f * (xz + yw);
mat._14 = 0.0f;

mat._21 = 2.0f * (xy + zw);
mat._22 = 1.0f - 2.0f * (xx + zz);
mat._23 = 2.0f * (yz - xw);
mat._24 = 0.0f;

mat._31 = 2.0f * (xz - yw);
mat._32 = 2.0f * (yz + xw);
mat._33 = 1.0f - 2.0f * (xx + yy);
mat._34 = 0.0f;

mat._41 = 0.0f;
mat._42 = 0.0f;
mat._43 = 0.0f;
mat._44 = 1.0f;

return mat;
}

Matrix GetMatrix()
{
static UCanvas* Canvas = nullptr;

if (Canvas == nullptr)
{
Canvas = UObject::FindObject<UCanvas>("Canvas Transient.DebugCanvasObject");
}

if (!Canvas)
{
return Matrix{};
}

uintptr_t lodalele;

#if defined(__LP64__)
lodalele = 0x270;
#else
lodalele = 0x200;
#endif

return *(Matrix*)((uintptr_t)Canvas + lodalele);

}


bool WorldToScreenPlayer(FVector pos, FVector &screen, int *distance)
{
Matrix ViewMatrix = GetMatrix();

screen = {};
*distance = 0;

float screenW = (ViewMatrix.m[0][3] * pos.X) + (ViewMatrix.m[1][3] * pos.Y) + (ViewMatrix.m[2][3] * pos.Z + ViewMatrix.m[3][3]);
if (screenW < 0.0001f)
return false;

*distance = (screenW / 100);
float screenY = (ViewMatrix.m[0][1] * pos.X) + (ViewMatrix.m[1][1] * pos.Y) + (ViewMatrix.m[2][1] * (pos.Z + 85) + ViewMatrix.m[3][1]);
float screenX = (ViewMatrix.m[0][0] * pos.X) + (ViewMatrix.m[1][0] * pos.Y) + (ViewMatrix.m[2][0] * pos.Z + ViewMatrix.m[3][0]);
screen.Y = (screenHeight / 2.f) - (screenHeight / 2.f) * screenY / screenW;
screen.X = (screenWidth / 2.f) + (screenWidth / 2.f) * screenX / screenW;
float y1 = (screenHeight / 2.f) - (ViewMatrix.m[0][1] * pos.X + ViewMatrix.m[1][1] * pos.Y + ViewMatrix.m[2][1] * (pos.Z - 95) + ViewMatrix.m[3][1]) * (screenHeight / 2.f) / screenW;
screen.Z = y1 - screen.Y;

return !(screen.X == 0 && screen.Y == 0 && screen.Z == 0);
}

bool WorldToScreenBone(FVector Position, FVector2D *Screen)
{
Matrix ViewMatrix = GetMatrix();

float ScreenW = (ViewMatrix.m[0][3] * Position.X) + (ViewMatrix.m[1][3] * Position.Y) + (ViewMatrix.m[2][3] * Position.Z + ViewMatrix.m[3][3]);
if (ScreenW < 0.0001f)
return false;

ScreenW = 1 / ScreenW;
float SightX = (screenWidth / 2);
float SightY = (screenHeight / 2);

Screen->X = SightX + (ViewMatrix.m[0][0] * Position.X + ViewMatrix.m[1][0] * Position.Y + ViewMatrix.m[2][0] * Position.Z + ViewMatrix.m[3][0]) * ScreenW * SightX;
Screen->Y = SightY - (ViewMatrix.m[0][1] * Position.X + ViewMatrix.m[1][1] * Position.Y + ViewMatrix.m[2][1] * Position.Z + ViewMatrix.m[3][1]) * ScreenW * SightY;

return true;
}

#define W2S(w, s) UGameplayStatics::ProjectWorldToScreen(localController, w, true, s)
static uintptr_t gameoverlay_return_address = 0;

 

void AimAngle(FRotator &angles) {
if (angles.Pitch > 180)
angles.Pitch -= 360;
if (angles.Pitch < -180)
angles.Pitch += 360;

if (angles.Pitch < -75.f)
angles.Pitch = -75.f;
else if (angles.Pitch > 75.f)
angles.Pitch = 75.f;

while (angles.Yaw < -180.0f)
angles.Yaw += 360.0f;
while (angles.Yaw > 180.0f)
angles.Yaw -= 360.0f;
}
FRotator ClampAngles(FRotator inRot) {
    FRotator outRot = inRot;
    if (outRot.Pitch > 180)
        outRot.Pitch -= 360;
    if (outRot.Pitch < -180)
        outRot.Pitch += 360;

    if (outRot.Pitch < -75.f)
        outRot.Pitch = -75.f;
    else if (outRot.Pitch > 75.f)
        outRot.Pitch = 75.f;

    while (outRot.Yaw < -180.0f)
        outRot.Yaw += 360.0f;
    while (outRot.Yaw > 180.0f)
        outRot.Yaw -= 360.0f;
    return outRot;
}


void VectorAnglesRadar(Vector3 & forward, FVector & angles) {
    if (forward.X == 0.f && forward.Y == 0.f) {
        angles.X = forward.Z > 0.f ? -90.f : 90.f;
        angles.Y = 0.f;
    } else {
        angles.X = RAD2DEG(atan2(-forward.Z, forward.Magnitude(forward)));
        angles.Y = RAD2DEG(atan2(forward.Y, forward.X));
    }
    angles.Z = 0.f;
}
FRotator ToRotator(FVector local, FVector target) {
    FVector rotation = UKismetMathLibrary::Subtract_VectorVector(local, target);

    float hyp = sqrt(rotation.X * rotation.X + rotation.Y * rotation.Y);

    FRotator newViewAngle = {0};
    newViewAngle.Pitch = -atan(rotation.Z / hyp) * (180.f / (float) 3.14159265358979323846);
    newViewAngle.Yaw = atan(rotation.Y / rotation.X) * (180.f / (float) 3.14159265358979323846);
    newViewAngle.Roll = (float) 0.f;

    if (rotation.X >= 0.f)
        newViewAngle.Yaw += 180.0f;

    return newViewAngle;
}



#include "MTR/loda.h"
//#include "MTR/bullettrack.h"

void Line(ImDrawList *draw,FVector2D origin, FVector2D dest, ImColor color)
{
draw->AddLine({origin.X, origin.Y},{dest.X, dest.Y},color, 1.0f);
}

FVector2D pushToScreenBorder(FVector2D Pos, FVector2D screen, int borders, int offset) {
int x = (int)Pos.X;
int y = (int)Pos.Y;
if ((borders & 1) == 1) {
y = 0 - offset;
}
if ((borders & 2) == 2) {
x = (int)screen.X + offset;
}
if ((borders & 4) == 4) {
y = (int)screen.Y + offset;
}
if ((borders & 8) == 8) {
x = 0 - offset;
}
return FVector2D(x, y);
}

 

void Box4Line(ImDrawList* draw, float thicc, int x, int y, int w, int h, ImU32 color) {
int iw = w / 3;
int ih = h / 5;

draw->AddLine(ImVec2(x, y), ImVec2(x + iw, y), color, thicc);
draw->AddLine(ImVec2(x, y), ImVec2(x, y + ih), color, thicc);

draw->AddLine(ImVec2(x + w - iw, y), ImVec2(x + w, y), color, thicc);
draw->AddLine(ImVec2(x + w - 1, y), ImVec2(x + w - 1, y + ih), color, thicc);

// Bottom Left Corner
draw->AddLine(ImVec2(x, y + h), ImVec2(x + iw, y + h), color, thicc);
draw->AddLine(ImVec2(x, y + h - ih), ImVec2(x, y + h), color, thicc);

// Bottom Right Corner
draw->AddLine(ImVec2(x + w - iw, y + h), ImVec2(x + w, y + h), color, thicc);
draw->AddLine(ImVec2(x + w - 1, y + h - ih), ImVec2(x + w - 1, y + h), color, thicc);
}


 

std::string getDayName() {
time_t now = time(0);
struct tm* timeinfo = localtime(&now);
const char* weekday[] = { "Sunday,", "Monday,", "Tuesday,", "Wednesday,", "Thursday,", "Friday,", "Saturday," };
return weekday[timeinfo->tm_wday];
}

std::string getAMPM() {
time_t now = time(0);
struct tm* timeinfo = localtime(&now);
return (timeinfo->tm_hour < 12) ? "AM IST" : "PM IST";
}


bool isInsideFOV(int x, int y) {
if (!Config.AimBot.Enable)
return true;
int circle_x = glWidth / 2;
int circle_y = glHeight / 2;
int rad = (int)Config.AimBot.FOV;
return (x - circle_x) * (x - circle_x) + (y - circle_y) * (y - circle_y) <= rad * rad; }


#ifndef IM_PI
#define IM_PI 3.14159265358979323846f
#endif
#undef RAD2DEG
#define RAD2DEG(x) ((float)(x) * (float)(180.f / IM_PI))
#undef DEG2RAD
#define DEG2RAD(x) ((float)(x) * (float)(IM_PI / 180.f))
#define sub_3793CC
#define _ReadStatusReg
#undef ARM64_SYSREG
#define ARM64_SYSREG

float VectorSizeSquared(FVector vec) {
    if (!std::isfinite(vec.X) || !std::isfinite(vec.Y) || !std::isfinite(vec.Z)) return 0.f;
    return vec.X * vec.X + vec.Y * vec.Y + vec.Z * vec.Z;
}

float VectorDistance(FVector a, FVector b) {
    if (!std::isfinite(a.X) || !std::isfinite(a.Y) || !std::isfinite(a.Z)) return 0.f;
    if (!std::isfinite(b.X) || !std::isfinite(b.Y) || !std::isfinite(b.Z)) return 0.f;
    float dx = a.X - b.X;
    float dy = a.Y - b.Y;
    float dz = a.Z - b.Z;
    return sqrtf(dx * dx + dy * dy + dz * dz);
}

float VectorDot(FVector a, FVector b) {
    if (!std::isfinite(a.X) || !std::isfinite(a.Y) || !std::isfinite(a.Z)) return 0.f;
    if (!std::isfinite(b.X) || !std::isfinite(b.Y) || !std::isfinite(b.Z)) return 0.f;
    return a.X * b.X + a.Y * b.Y + a.Z * b.Z;
}

FVector VectorMultiply(FVector vec, float scalar) {
    if (!std::isfinite(vec.X) || !std::isfinite(vec.Y) || !std::isfinite(vec.Z) || !std::isfinite(scalar))
        return { 0.f, 0.f, 0.f };
    return { vec.X * scalar, vec.Y * scalar, vec.Z * scalar };
}

FVector VectorAdd(FVector a, FVector b) {
    if (!std::isfinite(a.X) || !std::isfinite(a.Y) || !std::isfinite(a.Z)) return { 0.f, 0.f, 0.f };
    if (!std::isfinite(b.X) || !std::isfinite(b.Y) || !std::isfinite(b.Z)) return { 0.f, 0.f, 0.f };
    return { a.X + b.X, a.Y + b.Y, a.Z + b.Z };
}

FVector VectorSubtract(FVector a, FVector b) {
    if (!std::isfinite(a.X) || !std::isfinite(a.Y) || !std::isfinite(a.Z)) return { 0.f, 0.f, 0.f };
    if (!std::isfinite(b.X) || !std::isfinite(b.Y) || !std::isfinite(b.Z)) return { 0.f, 0.f, 0.f };
    return { a.X - b.X, a.Y - b.Y, a.Z - b.Z };
}

inline float VectorSize(const FVector& vec) {
    if (!std::isfinite(vec.X) || !std::isfinite(vec.Y) || !std::isfinite(vec.Z)) return 0.f;
    return sqrtf(vec.X * vec.X + vec.Y * vec.Y + vec.Z * vec.Z);
}

// Полный список костей: 0=Head 1=Neck 2=Chest 3=Pelvis 4=hand_r 5=hand_l 6=foot_r 7=foot_l
static const char* g_AimBoneList[] = {
    "Head", "neck_01", "spine_03", "pelvis",
    "hand_r", "hand_l", "foot_r", "foot_l"
};
static const int g_AimBoneCount = 8;

// Приоритет fallback по близости к центру экрана если приоритетная кость за стеной
struct AimResult {
    ASTExtraPlayerCharacter* player = nullptr;
    FVector bonePos = {0,0,0};
    int boneIndex = 0;
};

static bool IsBoneLOS(ASTExtraPlayerCharacter* target, const FVector& bonePos, ASTExtraPlayerController* lc) {
    if (!lc) return true;
    return lc->LineOfSightTo(target, {0, 0, 0}, true);
}

AimResult GetTargetByCrossDist() {
    AimResult result;
    float bestValue = std::numeric_limits<float>::infinity();

    auto Actors = GetActors();
    auto* localPlayer = g_LocalPlayer;
    auto* localController = g_LocalController;

    if (!localPlayer || !localController || !localController->PlayerCameraManager) return result;

    FVector camLoc = localController->PlayerCameraManager->CameraCache.POV.Location;
    FRotator camRot = localController->PlayerCameraManager->CameraCache.POV.Rotation;
    FVector2D center = { (float)(glWidth / 2), (float)(glHeight / 2) };

    int preferredBone = Config.AimBot.Target;
    if (preferredBone < 0 || preferredBone >= g_AimBoneCount) preferredBone = 0;

    for (size_t i = 0; i < Actors.size(); i++) {
        auto* Actor = Actors[i];
        if (isObjectInvalid(Actor)) continue;
        if (!Actor->IsA(ASTExtraPlayerCharacter::StaticClass())) continue;

        auto* Player = static_cast<ASTExtraPlayerCharacter*>(Actor);
        if (Player->PlayerKey == localPlayer->PlayerKey) continue;
        if (Player->TeamID == localPlayer->TeamID) continue;
        if (Player->bDead) continue;
        if (Config.AimBot.IgnoreKnocked && Player->Health == 0.0f) continue;
        if (Config.AimBot.IgnoreBot && Player->bEnsure) continue;

        float distance = localPlayer->GetDistanceTo(Player) / 100.f;
        if (!std::isfinite(distance) || distance > Config.AimBot.AimDist) continue;

        FVector targetPos = Player->GetBonePos(g_AimBoneList[preferredBone], {});
        if (!std::isfinite(targetPos.X) || !std::isfinite(targetPos.Y) || !std::isfinite(targetPos.Z)) continue;

        if (Config.AimBot.VisCheck) {
            if (!IsBoneLOS(Player, targetPos, localController)) continue;
        }

        if (Config.AimBot.AimBy == 0) {
            // FOV: считаем угловое расстояние от прицела до цели
            FRotator toTarget = ToRotator(camLoc, targetPos);
            float dPitch = toTarget.Pitch - camRot.Pitch;
            float dYaw = toTarget.Yaw - camRot.Yaw;
            // нормализация
            while (dYaw > 180.f) dYaw -= 360.f;
            while (dYaw < -180.f) dYaw += 360.f;
            while (dPitch > 180.f) dPitch -= 360.f;
            while (dPitch < -180.f) dPitch += 360.f;

            // Конвертируем FOV пиксели в градусы (approx)
            float fovDeg = Config.AimBot.FOV / (float)(glHeight) * 90.f;
            if (std::abs(dPitch) > fovDeg || std::abs(dYaw) > fovDeg) continue;

            float angDist = sqrtf(dPitch * dPitch + dYaw * dYaw);
            if (angDist < bestValue) {
                bestValue = angDist;
                result.player = Player;
                result.bonePos = targetPos;
                result.boneIndex = preferredBone;
            }
        } else {
            if (distance < bestValue) {
                bestValue = distance;
                result.player = Player;
                result.bonePos = targetPos;
                result.boneIndex = preferredBone;
            }
        }
    }
    return result;
}

void EnhancedAimbot() {
    if (!Config.AimBot.Enable) return;

    AimResult ar = GetTargetByCrossDist();
    if (!ar.player || ar.player->bDead) return;

    auto* target = ar.player;
    auto* localPlayer = g_LocalPlayer;
    auto* localController = g_LocalController;

    if (!localPlayer || !localController || !localController->PlayerCameraManager) return;

    bool isADS = localPlayer->bIsGunADS;
    bool isFiring = localPlayer->bIsWeaponFiring;
    bool aimActive = false;

    int triggerType = Config.AimBot.Trigger;
    if (triggerType == 0)      aimActive = true;
    else if (triggerType == 1) aimActive = isFiring;
    else if (triggerType == 2) aimActive = isADS;
    else if (triggerType == 3) aimActive = isFiring && isADS;
    else if (triggerType == 4) aimActive = isFiring || isADS;

    if (!aimActive) return;

    float bulletSpeed = 750.f;
    if (localPlayer->WeaponManagerComponent) {
        auto* wm = localPlayer->WeaponManagerComponent;
        auto* weapon = (ASTExtraShootWeapon*)wm->CurrentWeaponReplicated;
        if (weapon && weapon->ShootWeaponComponent && weapon->ShootWeaponComponent->ShootWeaponEntityComponent) {
            bulletSpeed = weapon->ShootWeaponComponent->ShootWeaponEntityComponent->BulletFireSpeed;
        }
    }
    if (bulletSpeed < 50.f || !std::isfinite(bulletSpeed)) bulletSpeed = 750.f;

    // Используем уже выбранную видимую кость из GetTargetByCrossDist
    FVector targetAimPos = ar.bonePos;
    if (!std::isfinite(targetAimPos.X) || !std::isfinite(targetAimPos.Y) || !std::isfinite(targetAimPos.Z)) return;

    if (Config.AimBot.Pred) {
        FVector Velocity = target->GetVelocity();
        FVector localPos = localController->PlayerCameraManager->CameraCache.POV.Location;
        FVector relativePos = VectorSubtract(targetAimPos, localPos);

        float a = VectorSizeSquared(Velocity) - bulletSpeed * bulletSpeed;
        float b = 2 * VectorDot(relativePos, Velocity);
        float c = VectorSizeSquared(relativePos);
        float discriminant = b * b - 4 * a * c;

        if (std::isfinite(a) && std::isfinite(b) && std::isfinite(c) && discriminant >= 0) {
            float sqrtDisc = sqrtf(discriminant);
            float t = (-b - sqrtDisc) / (2 * a);
            if (t > 0.f && t < 1.5f) {
                targetAimPos = VectorAdd(targetAimPos, VectorMultiply(Velocity, t));
            }
        }
    }

    FVector localPos = localController->PlayerCameraManager->CameraCache.POV.Location;
    FRotator camRot = localController->PlayerCameraManager->CameraCache.POV.Rotation;
    FRotator aimRot = ToRotator(localPos, targetAimPos);
    aimRot.Pitch -= camRot.Pitch;
    aimRot.Yaw -= camRot.Yaw;

    AimAngle(aimRot);

    float smoothing = std::max(1.0f, Config.AimBot.Smooth);

    FRotator controlRot = localController->ControlRotation;
    controlRot.Pitch += aimRot.Pitch / smoothing;
    controlRot.Yaw += aimRot.Yaw / smoothing;

    if (localPlayer && localPlayer->WeaponManagerComponent) {
        auto WeaponManagerComponent = localPlayer->WeaponManagerComponent;
        if (WeaponManagerComponent->CurrentWeaponReplicated) {
            auto currentWeapon = WeaponManagerComponent->CurrentWeaponReplicated;
            if (currentWeapon->IsA(ASTExtraShootWeapon::StaticClass())) {
                auto shootWeapon = (ASTExtraShootWeapon*)currentWeapon;
                if (shootWeapon->ShootWeaponComponent &&
                    shootWeapon->ShootWeaponComponent->ShootWeaponEntityComponent) {
                    shootWeapon->ShootWeaponComponent->ShootWeaponEntityComponent->GameDeviationFactor = 0.0f;
                }
                if (Config.AimBot.Recc > 0.0f && localPlayer->bIsWeaponFiring) {
                        controlRot.Pitch -= Config.AimBot.Recc * 0.3f;
                        AimAngle(controlRot);
                }
            }
        }
    }

    localController->SetControlRotation(controlRot, "");
}





#define W2S_DIRECT(worldPos, screenPos) g_LocalController->ProjectWorldLocationToScreen(worldPos, true, screenPos)

void(*orig_UpdateVolley)(USTExtraShootWeaponComponent* a1, FVector TargetLoc, FVector* start, FRotator* BulletRot, FVector* BulletDir);

void UpdateVolley(USTExtraShootWeaponComponent* a1, FVector TargetLoc, FVector* start, FRotator* BulletRot, FVector* BulletDir) {
if (Config.SilentAim.Enable && g_LocalPlayer && g_LocalController) {
ASTExtraPlayerCharacter* Target = nullptr;
float bestValue = std::numeric_limits<float>::infinity();
auto Actors = GetActors();
FVector2D center = { (float)(glWidth / 2), (float)(glHeight / 2) };
float maxDist = Config.SilentAim.MaxDistance * 100.0f;

for (auto Actor : Actors) {
if (isObjectInvalid(Actor)) continue;
if (!Actor->IsA(ASTExtraPlayerCharacter::StaticClass())) continue;
auto* Player = (ASTExtraPlayerCharacter*)Actor;
if (Player->PlayerKey == g_LocalPlayer->PlayerKey) continue;
if (Player->TeamID == g_LocalPlayer->TeamID) continue;
if (Player->bDead) continue;
if (Config.SilentAim.IgnoreKnocked && Player->Health == 0.0f) continue;
if (Config.SilentAim.IgnoreBot && Player->bEnsure) continue;

float distance = g_LocalPlayer->GetDistanceTo(Player);
if (distance > maxDist) continue;

if (Config.SilentAim.VisibleCheck) {
if (!g_LocalController->LineOfSightTo(Player, {0, 0, 0}, true)) continue;
}

const char* targetBone = "Head";
switch ((int)Config.SilentAim.TargetBone) {
case 0: targetBone = "Head"; break;
case 1: targetBone = "neck_01"; break;
case 2: targetBone = "spine_03"; break;
case 3: targetBone = "pelvis"; break;
case 4: {
const char* bones[] = { "Head", "neck_01", "spine_03", "pelvis", "hand_r", "hand_l" };
targetBone = bones[rand() % 6];
break;
}
default: targetBone = "Head"; break;
}

FVector bonePos = Player->GetBonePos(targetBone, {});

float currentValue = distance; // используем 3D дистанцию как основной критерий

if (Config.SilentAim.FOV > 0.0f) {
FVector2D screenPos;
if (W2S_DIRECT(bonePos, &screenPos)) {
int circle_x = glWidth / 2;
int circle_y = glHeight / 2;
float rad = Config.SilentAim.FOV * 0.5f;
float dx = screenPos.X - circle_x;
float dy = screenPos.Y - circle_y;
if (dx * dx + dy * dy > rad * rad) continue;
currentValue = sqrtf(dx * dx + dy * dy); // в FOV-режиме сортируем по экранному расстоянию
} else {
// W2S не сработал - фолбэк: проверяем угол через 3D
FVector localPos = g_LocalPlayer->GetBonePos("Head", {});
FVector toTarget = VectorSubtract(bonePos, localPos);
float dist3d = VectorSize(toTarget);
if (dist3d < 1.f) continue;
// грубая угловая проверка: FOV пикселей -> примерно FOV/10 градусов
FRotator camRot = g_LocalController->GetControlRotation();
FRotator toRot = ToRotator(localPos, bonePos);
float pitchDiff = fabsf(toRot.Pitch - camRot.Pitch);
float yawDiff = fabsf(toRot.Yaw - camRot.Yaw);
if (yawDiff > 180.f) yawDiff = 360.f - yawDiff;
float angleDiff = sqrtf(pitchDiff * pitchDiff + yawDiff * yawDiff);
if (angleDiff > Config.SilentAim.FOV / 10.f) continue;
currentValue = angleDiff;
}
}

if (currentValue < bestValue) {
bestValue = currentValue;
Target = Player;
}
}

if (Target && !Target->bDead) {
bool triggerOk = false;
switch (Config.SilentAim.Trigger) {
case 0: triggerOk = true; break;
case 1: triggerOk = g_LocalPlayer->bIsWeaponFiring; break;
case 2: triggerOk = g_LocalPlayer->bIsGunADS; break;
case 3: triggerOk = g_LocalPlayer->bIsWeaponFiring || g_LocalPlayer->bIsGunADS; break;
default: triggerOk = false; break;
}

if (triggerOk) {
const char* targetBone = "Head";
switch ((int)Config.SilentAim.TargetBone) {
case 0: targetBone = "Head"; break;
case 1: targetBone = "neck_01"; break;
case 2: targetBone = "spine_03"; break;
case 3: targetBone = "pelvis"; break;
case 4: {
const char* bones[] = { "Head", "neck_01", "spine_03", "pelvis", "hand_r", "hand_l" };
targetBone = bones[rand() % 6];
break;
}
default: targetBone = "Head"; break;
}

FVector targetAimPos = Target->GetBonePos(targetBone, {});
if (std::isfinite(targetAimPos.X) && std::isfinite(targetAimPos.Y) && std::isfinite(targetAimPos.Z)) {

float bulletSpeed = 750.f;
if (a1 && a1->ShootWeaponEntityComponent) {
bulletSpeed = a1->ShootWeaponEntityComponent->BulletFireSpeed;
}
if (bulletSpeed < 50.f || !std::isfinite(bulletSpeed)) bulletSpeed = 750.f;

FVector localPos = *start;
FVector relativePos = VectorSubtract(targetAimPos, localPos);
FVector Velocity = Target->GetVelocity();
float va = VectorSizeSquared(Velocity) - bulletSpeed * bulletSpeed;
float vb = 2.f * VectorDot(relativePos, Velocity);
float vc = VectorSizeSquared(relativePos);
float discriminant = vb * vb - 4.f * va * vc;

if (std::isfinite(va) && std::isfinite(vb) && std::isfinite(vc) && discriminant >= 0.f) {
float sqrtDisc = sqrtf(discriminant);
float t1 = (-vb - sqrtDisc) / (2.f * va);
float t2 = (-vb + sqrtDisc) / (2.f * va);
float t = (t1 > 0.f) ? t1 : ((t2 > 0.f) ? t2 : -1.f);
if (t > 0.f && t < 1.5f) {
targetAimPos = VectorAdd(targetAimPos, VectorMultiply(Velocity, t));
}
} else {
float dist = VectorSize(relativePos);
if (std::isfinite(dist) && dist > 0.f) {
float timeToTravel = dist / bulletSpeed;
targetAimPos = VectorAdd(targetAimPos, VectorMultiply(Velocity, timeToTravel));
}
}

FRotator newRot = ToRotator(localPos, targetAimPos);
BulletRot->Pitch = newRot.Pitch;
BulletRot->Yaw = newRot.Yaw;

FVector newDir = VectorSubtract(targetAimPos, localPos);
float dirLen = VectorSize(newDir);
if (std::isfinite(dirLen) && dirLen > 0.f) {
*BulletDir = { newDir.X / dirLen, newDir.Y / dirLen, newDir.Z / dirLen };
}
}
}
}
}

if (orig_UpdateVolley) {
orig_UpdateVolley(a1, TargetLoc, start, BulletRot, BulletDir);
}
}




// ── Alert helpers ────────────────────────────────────────────────────────────
#ifndef DEG2RAD
#define DEG2RAD(x) ((float)(x) * (float)(M_PI / 180.f))
#endif

void RotateTriangle(std::array<Vector3, 3> &points, float rotation) {
    const auto center = (points[0] + points[1] + points[2]) / 3;
    for (auto &p : points) {
        p = p - center;
        const float tmp_x = p.X;
        const float tmp_y = p.Y;
        const float theta = DEG2RAD(rotation);
        const float c = cosf(theta), s = sinf(theta);
        p.X = tmp_x * c - tmp_y * s;
        p.Y = tmp_x * s + tmp_y * c;
        p = p + center;
    }
}

// Проецирует мировую позицию врага на 2D-радар вокруг центра экрана
FVector WorldToRadar(float cameraYaw, FVector myPos, FVector enemyPos,
                     void* /*unused1*/, void* /*unused2*/,
                     Vector3 screenSize, bool& /*outOnScreen*/) {
    // Вектор от нас к врагу в мировом пространстве
    float dx = enemyPos.X - myPos.X;
    float dy = enemyPos.Y - myPos.Y;

    // Поворачиваем в пространство камеры (yaw)
    // В UE: X=вперёд, Y=вправо; yaw растёт по часовой
    float yawRad = DEG2RAD(cameraYaw);
    float cosY = cosf(yawRad), sinY = sinf(yawRad);

    // forward = проекция на ось X камеры, right = проекция на ось Y камеры
    float forward =  dx * cosY + dy * sinY;
    float right   = -dx * sinY + dy * cosY;

    // Нормализуем
    float len = sqrtf(forward * forward + right * right);
    if (len > 0.0f) { forward /= len; right /= len; }

    // На экране: вверх = -forward (враг впереди → стрелка вверху)
    //            вправо = +right
    float cx = screenSize.X / 2.0f;
    float cy = screenSize.Y / 2.0f;
    return FVector(cx + right * cx, cy - forward * cy, 0.f);
}

// ── Forward declarations ─────────────────────────────────────────────────────
using on_change_callback = void(*)(int);
void RenderSkinItem(std::string label, CSkinsInfo& skins, on_change_callback cb = nullptr);
// ─────────────────────────────────────────────────────────────────────────────

void DrawESP(ImDrawList *draw) {
 


if (anticrack) {
 ImVec2 P1, P2;
 ImDrawList* pDrawList;
 const auto& CurrentWindowPos = ImGui::GetWindowPos();
 const auto& pBackgroundDrawList = ImGui::GetBackgroundDrawList();
 
 P1 = ImVec2(10000.000f, 10000.000f);
 P1.x += CurrentWindowPos.x;
 P1.y += CurrentWindowPos.y;
 P2 = ImVec2(-600.000f, -500.000f);
 P2.x += CurrentWindowPos.x;
 P2.y += CurrentWindowPos.y;
 pDrawList = pBackgroundDrawList;
 draw->AddRectFilled(P1,P2, IM_COL32(0, 0, 0, 255), 0);

 }


  if(Thundertest){
std::string credit = oxorany("");

// Font size = screen height ke hisaab se scale (proportional)
float fontSize = (float)glHeight * 0.03f; // 2.5% of screen height

// Text ka size nikaalo
ImVec2 textSize = ImGui::CalcTextSize(credit.c_str(), 0, false, -1.0f);

// Center position (X = middle, Y = 10% screen height)
float posX = (glWidth  / 2.0f) - (textSize.x / 2.0f);
float posY = (glHeight * 0.12f);  

// Draw text
ImGui::GetForegroundDrawList()->AddText(
pRegularFont,
fontSize,
ImVec2(posX, posY),
IM_COL32(255, 0, 0, 255),credit.c_str()
);

}
auto Actors = GetActors();

int totalEnemies = 0, totalBots = 0;

ASTExtraPlayerCharacter *localPlayer = 0;
ASTExtraPlayerController *localController = 0;
 


 for (int i = 0; i < Actors.size(); i++) {
auto Actor = Actors[i];
if (isObjectInvalid(Actor))
continue;

if (Actor->IsA(ASTExtraPlayerController::StaticClass())) {
localController = (ASTExtraPlayerController *) Actor;
break;
}}

if (localController) {
for (int i = 0; i < Actors.size(); i++) {
auto Actor = Actors[i];
if (isObjectInvalid(Actor))
continue;

if (Actor->IsA(ASTExtraPlayerCharacter::StaticClass())) {
if (((ASTExtraPlayerCharacter *) Actor)->PlayerKey == localController->PlayerKey) {
localPlayer = (ASTExtraPlayerCharacter *) Actor;
break;
}}}


 


if (localPlayer) {
if (localPlayer->PartHitComponent) {
auto ConfigCollisionDistSqAngles = localPlayer->PartHitComponent->ConfigCollisionDistSqAngles;
for (int j = 0; j < ConfigCollisionDistSqAngles.Num(); j++) {
ConfigCollisionDistSqAngles[j].Angle = 180.0f;
}
localPlayer->PartHitComponent->ConfigCollisionDistSqAngles = ConfigCollisionDistSqAngles;
}

if (Config.ESPMenu.TargetLine) {
ASTExtraPlayerCharacter* Target = nullptr;
{
    AimResult ar = GetTargetByCrossDist();
    Target = ar.player;
}

long PlayerAimLineColor = IM_COL32(225, 225, 255, 255); // White color  

if (Target) {
FVector RootPos = Target->GetBonePos("Root", {});
ImVec2 RootPosSC;
if (WorldToScreenBone(RootPos, (FVector2D*)&RootPosSC)) {
draw->AddLine(
RootPosSC,
{ (float)glWidth / 2, (float)glHeight },
PlayerAimLineColor,
0.5f // line thickness
);
}}}
 
FVector ViewPosY{0, 0, 0};
if (localPlayer) {
ViewPosY = localPlayer->GetBonePos("Head", {});
ViewPosY.Z += 10.f;
 } 

 

if (Config.AimBot.Enable) {
float dashOffset = ImGui::GetTime() * 30.0f;
float dashLength = 10.0f;
float dashGap = 5.0f;
ImVec2 fovCenter = ImVec2(glWidth / 2, glHeight / 2);
float fovRadius = Config.AimBot.FOV;
int fovSegments = 100;
float fovAngleStep = 2 * 3.14159f / fovSegments;
for (int fi = 0; fi < fovSegments; fi++) {
    float angle = fi * fovAngleStep;
    float fx = fovCenter.x + fovRadius * cos(angle);
    float fy = fovCenter.y + fovRadius * sin(angle);
    float nextAngle = (fi + 1) * fovAngleStep;
    float nfx = fovCenter.x + fovRadius * cos(nextAngle);
    float nfy = fovCenter.y + fovRadius * sin(nextAngle);
    float dashStart = fmod((fi * dashLength + dashOffset), (dashLength + dashGap));
    if (dashStart < dashLength)
        draw->AddLine(ImVec2(fx, fy), ImVec2(nfx, nfy), IM_COL32(255, 255, 255, 200), 1.5f);
}}

if (Config.SilentAim.Enable && Config.SilentAim.FOV > 0.0f) {
ImVec2 saCenter = ImVec2(glWidth / 2, glHeight / 2);
float saRadius = Config.SilentAim.FOV * 0.5f;
draw->AddCircle(saCenter, saRadius, IM_COL32(160, 80, 255, 200), 100, 1.5f);
}

for (auto &i : Actors) {
auto Actor = i;
if (isObjectInvalid(Actor))
continue;
if (Actor->IsA(ASTExtraPlayerCharacter::StaticClass())) {

auto Player = (ASTExtraPlayerCharacter *)Actor;
if(Player->bHidden)
continue;

float Distance = localPlayer->GetDistanceTo(Player) / 100.0f;
if (Distance > 500.0f) continue;
if (Player->PlayerKey == localController->PlayerKey) continue;
if (Player->TeamID == localController->TeamID) continue;
if (Player->bDead) continue;
if (Player->bHidden) continue;

if (Player->bEnsure) totalBots++;
else                 totalEnemies++;

// ── Alert (стрелка-индикатор врага за экраном) ───────────────
if (Config.ESPMenu.ALEART) {
    if (!(Config.ESPMenu.NoBot && Player->bEnsure)) {
        static std::map<uintptr_t, Vector3> prevArrowPositions;
        static std::map<uintptr_t, float>   prevArrowDistances;
        static std::map<uintptr_t, float>   prevAngles;

        bool shit = false;
        FVector MyPosition, EnemyPosition;

        // MyPosition = localPlayer, EnemyPosition = enemy Player
        ASTExtraVehicleBase* CurrentVehicle = localPlayer->CurrentVehicle;
        if (CurrentVehicle) MyPosition = CurrentVehicle->RootComponent->RelativeLocation;
        else                MyPosition = localPlayer->RootComponent->RelativeLocation;

        ASTExtraVehicleBase* CurrentVehicleA = Player->CurrentVehicle;
        if (CurrentVehicleA) EnemyPosition = CurrentVehicleA->RootComponent->RelativeLocation;
        else                 EnemyPosition = Player->RootComponent->RelativeLocation;

        float distAlert = sqrtf(
            powf(MyPosition.X - EnemyPosition.X, 2) +
            powf(MyPosition.Y - EnemyPosition.Y, 2) +
            powf(MyPosition.Z - EnemyPosition.Z, 2)) / 100.f;

        bool isMoving = false;
        if (localPlayer->CharacterMovement) {
            float speed = sqrtf(
                localPlayer->CharacterMovement->Velocity.X * localPlayer->CharacterMovement->Velocity.X +
                localPlayer->CharacterMovement->Velocity.Y * localPlayer->CharacterMovement->Velocity.Y +
                localPlayer->CharacterMovement->Velocity.Z * localPlayer->CharacterMovement->Velocity.Z);
            isMoving = speed > 10.0f;
        }

        FVector EntityPos = WorldToRadar(
            localController->PlayerCameraManager->CameraCache.POV.Rotation.Yaw,
            MyPosition, EnemyPosition, NULL, NULL,
            Vector3(glWidth, glHeight, 0), shit);

        FVector angle = FVector();
        Vector3 forward = Vector3((float)(glWidth / 2) - EntityPos.X, (float)(glHeight / 2) - EntityPos.Y, 0.0f);
        VectorAnglesRadar(forward, angle);

        float& prevAngle = prevAngles[(uintptr_t)Player];
        if (prevAngle == 0) prevAngle = angle.Y + 180.f;
        float angleInterpSpeed = 5.0f * ImGui::GetIO().DeltaTime;
        float currentAngle = prevAngle + (angle.Y + 180.f - prevAngle) * angleInterpSpeed;
        prevAngle = currentAngle;

        float& prevDistance = prevArrowDistances[(uintptr_t)Player];
        if (prevDistance == 0) prevDistance = 55.f * 2.0f;
        float targetDistance = isMoving ? 100.f * 2.0f : 75.f * 2.0f;
        float distanceInterpSpeed = 3.0f * ImGui::GetIO().DeltaTime;
        float currentDistance = prevDistance + (targetDistance - prevDistance) * distanceInterpSpeed;
        prevDistance = currentDistance;

        const auto angle_yaw_rad = DEG2RAD(currentAngle);
        const auto new_point_x = (glWidth / 2) + currentDistance * cosf(angle_yaw_rad);
        const auto new_point_y = (glHeight / 2) + currentDistance * sinf(angle_yaw_rad);

        Vector3& prevPos = prevArrowPositions[(uintptr_t)Player];
        if (prevPos.X == 0 && prevPos.Y == 0) prevPos = Vector3(new_point_x, new_point_y, 0);

        float posInterpSpeed = 8.0f * ImGui::GetIO().DeltaTime;
        Vector3 currentPos = Vector3(
            prevPos.X + (new_point_x - prevPos.X) * posInterpSpeed,
            prevPos.Y + (new_point_y - prevPos.Y) * posInterpSpeed, 0);
        prevPos = currentPos;

        float arrowWidth  = 8.f;
        float arrowHeight = 16.f;
        std::array<Vector3, 3> points {
            Vector3(currentPos.X - arrowWidth / 2, currentPos.Y - arrowHeight / 2, 0.f),
            Vector3(currentPos.X + arrowWidth / 2, currentPos.Y, 0.f),
            Vector3(currentPos.X - arrowWidth / 2, currentPos.Y + arrowHeight / 2, 0.f)
        };
        RotateTriangle(points, currentAngle);

        ImVec2 p1(points.at(0).X, points.at(0).Y);
        ImVec2 p2(points.at(1).X, points.at(1).Y);
        ImVec2 p3(points.at(2).X, points.at(2).Y);

        draw->AddTriangleFilled(p1, p2, p3, ImColor(0, 255, 255, 255));
        draw->AddTriangle(p1, p2, p3, ImColor(255, 255, 255, 180), 1.5f);

        std::string distanceStr = std::to_string((int)distAlert) + "m";
        ImVec2 textSize = ImGui::CalcTextSize(distanceStr.c_str());
        ImVec2 textPos  = ImVec2(currentPos.X - textSize.x / 2, currentPos.Y + arrowHeight / 2 + 5.f);
        draw->AddRectFilled(
            ImVec2(textPos.x - 4, textPos.y - 2),
            ImVec2(textPos.x + textSize.x + 4, textPos.y + textSize.y + 2),
            ImColor(0, 0, 0, 120), 3.0f);
        draw->AddText(textPos, ImColor(255, 255, 255, 255), distanceStr.c_str());
    }
}

if (Config.ESPMenu.NoBot && Player->bEnsure) continue;

auto HeadPos   = Player->GetBonePos("Head",   {});
auto RootPos   = Player->GetBonePos("Root",   {});
auto foot_lPos = Player->GetBonePos("foot_l", {});

ImVec2 headPosSC, RootPosSC, foot_lPoSC;
ImVec2 pelvisPoSC, upper_rPoSC, lowerarm_rPoSC, hand_rPoSC;
ImVec2 upper_lPoSC, lowerarm_lPoSC, hand_lPoSC;
ImVec2 thigh_lPoSC, calf_lPoSC, foot_lPoSC2;
ImVec2 thigh_rPoSC, calf_rPoSC, foot_rPoSC;
ImVec2 neck_01PoSC, spine_01PoSC, spine_02PoSC, spine_03PoSC;

auto pelvis    = Player->GetBonePos("pelvis",    {});
auto upper_r   = Player->GetBonePos("upperarm_r",{});
auto lowerarm_r= Player->GetBonePos("lowerarm_r",{});
auto hand_r    = Player->GetBonePos("hand_r",    {});
auto upper_l   = Player->GetBonePos("upperarm_l",{});
auto lowerarm_l= Player->GetBonePos("lowerarm_l",{});
auto hand_l    = Player->GetBonePos("hand_l",    {});
auto thigh_l   = Player->GetBonePos("thigh_l",   {});
auto calf_l    = Player->GetBonePos("calf_l",    {});
auto foot_l2   = Player->GetBonePos("foot_l",    {});
auto thigh_r   = Player->GetBonePos("thigh_r",   {});
auto calf_r    = Player->GetBonePos("calf_r",    {});
auto foot_r    = Player->GetBonePos("foot_r",    {});
auto neck_01   = Player->GetBonePos("neck_01",   {});
auto spine_01  = Player->GetBonePos("spine_01",  {});
auto spine_02  = Player->GetBonePos("spine_02",  {});
auto spine_03  = Player->GetBonePos("spine_03",  {});

if (WorldToScreenBone(HeadPos,    (FVector2D*)&headPosSC)   &&
    WorldToScreenBone(foot_lPos,  (FVector2D*)&foot_lPoSC)  &&
    WorldToScreenBone(RootPos,    (FVector2D*)&RootPosSC)   &&
    WorldToScreenBone(thigh_l,   (FVector2D*)&thigh_lPoSC)  &&
    WorldToScreenBone(calf_l,    (FVector2D*)&calf_lPoSC)   &&
    WorldToScreenBone(foot_l2,   (FVector2D*)&foot_lPoSC2)  &&
    WorldToScreenBone(thigh_r,   (FVector2D*)&thigh_rPoSC)  &&
    WorldToScreenBone(calf_r,    (FVector2D*)&calf_rPoSC)   &&
    WorldToScreenBone(foot_r,    (FVector2D*)&foot_rPoSC)   &&
    WorldToScreenBone(neck_01,   (FVector2D*)&neck_01PoSC)  &&
    WorldToScreenBone(pelvis,    (FVector2D*)&pelvisPoSC)   &&
    WorldToScreenBone(spine_01,  (FVector2D*)&spine_01PoSC) &&
    WorldToScreenBone(spine_02,  (FVector2D*)&spine_02PoSC) &&
    WorldToScreenBone(spine_03,  (FVector2D*)&spine_03PoSC))
{
    float _bh  = std::abs(headPosSC.y - foot_lPoSC.y);
    float _bw  = _bh * 0.65f;
    float _bx  = headPosSC.x - _bw * 0.5f;
    float _by  = headPosSC.y;
    float _bx2 = _bx + _bw;
    float _by2 = _by + _bh;
    bool  _vis = localController->LineOfSightTo(Player, {0,0,0}, true);

    // ── Line ────────────────────────────────────────────────────
    if (Config.ESPMenu.Line) {
        ImVec2 screenBottom = ImVec2((float)glWidth / 2.0f, (float)glHeight);
        ImVec2 targetPos    = ImVec2(RootPosSC.x, RootPosSC.y);
        ImU32 lineGlow = _vis ? IM_COL32(0,120,255,55)  : IM_COL32(255,50,50,40);
        ImU32 lineCol  = _vis ? IM_COL32(0,160,255,255) : IM_COL32(255,55,55,230);
        draw->AddLine(screenBottom, targetPos, lineGlow, 3.5f);
        draw->AddLine(screenBottom, targetPos, lineCol,  1.3f);
    }

    // ── Name ────────────────────────────────────────────────────
    if (Config.ESPMenu.Name) {
        std::string nameStr;
        if (Player->bEnsure) {
            nameStr = "BOT";
        } else {
            std::string pn = Player->PlayerName.ToString();
            nameStr = pn.empty() ? "Player" : pn;
        }
        if (Config.ESPMenu.TeamID)
            nameStr += " (" + std::to_string(Player->TeamID) + ")";

        float nFontSz = 14.0f;
        ImVec2 nSz = pRegularFont ? pRegularFont->CalcTextSizeA(nFontSz, FLT_MAX, 0.0f, nameStr.c_str()) : ImGui::CalcTextSize(nameStr.c_str());
        float nPadX = 8.0f, nPadY = 3.0f;
        float nW = nSz.x + nPadX * 2.0f;
        float nH = nSz.y + nPadY * 2.0f;
        float nX = headPosSC.x - nW * 0.5f;
        float nY = _by - nH - 2.0f;
        draw->AddRectFilled(ImVec2(nX, nY), ImVec2(nX+nW, nY+nH), IM_COL32(10,10,10,215), 3.0f);
        draw->AddText(pRegularFont, nFontSz, ImVec2(nX+nPadX, nY+nPadY), IM_COL32(255,255,255,255), nameStr.c_str());
    }

    // ── Box ─────────────────────────────────────────────────────
    if (Config.ESPMenu.Box) {
        ImU32 boxCol  = _vis ? IM_COL32(0,200,255,255) : IM_COL32(255,50,50,255);
        ImU32 fillCol = _vis ? IM_COL32(0,150,255,18)  : IM_COL32(255,50,50,15);
        draw->AddRectFilled(ImVec2(_bx,_by), ImVec2(_bx2,_by2), fillCol, 5.0f);
        draw->AddRect(ImVec2(_bx,_by), ImVec2(_bx2,_by2), boxCol, 5.0f, 0, 1.5f);
    }

    // ── Skeleton ────────────────────────────────────────────────
    if (Config.ESPMenu.Skeleton) {
        static std::vector<std::string> right_arm{"neck_01","clavicle_r","upperarm_r","lowerarm_r","hand_r","item_r"};
        static std::vector<std::string> left_arm {"neck_01","clavicle_l","upperarm_l","lowerarm_l","hand_l","item_l"};
        static std::vector<std::string> spine    {"Head","neck_01","spine_03","spine_02","spine_01","pelvis"};
        static std::vector<std::string> lower_r  {"pelvis","thigh_r","calf_r","foot_r"};
        static std::vector<std::string> lower_l  {"pelvis","thigh_l","calf_l","foot_l"};
        static std::vector<std::vector<std::string>> skeleton{right_arm,left_arm,spine,lower_r,lower_l};
        ImU32 skelCol = _vis ? IM_COL32(0,200,255,255) : IM_COL32(255,30,30,255);
        for (auto &boneChain : skeleton) {
            std::string last;
            for (std::string &cur : boneChain) {
                if (!last.empty()) {
                    FVector2D bFrom, bTo;
                    if (WorldToScreenBone(Player->GetBonePos(last.c_str(),{}), &bFrom) &&
                        WorldToScreenBone(Player->GetBonePos(cur.c_str(),{}),  &bTo))
                        draw->AddLine({bFrom.X,bFrom.Y},{bTo.X,bTo.Y}, skelCol, 1.2f);
                }
                last = cur;
            }
        }
    }

    // ── Health ──────────────────────────────────────────────────
    if (Config.ESPMenu.Health) {
        int CurHP = (int)std::max(0, std::min((int)Player->Health, (int)Player->HealthMax));
        int MaxHP = (int)Player->HealthMax;
        if (MaxHP <= 0) MaxHP = 100;
        ImU32 HPColor;
        if      (Player->Health <= 20) HPColor = IM_COL32(255,82,82,255);
        else if (Player->Health <= 50) HPColor = IM_COL32(235,210,50,255);
        else                           HPColor = IM_COL32(82,220,82,255);
        if (Player->Health == 0.0f && !Player->bDead) {
            HPColor = IM_COL32(80,80,80,200);
            CurHP   = Player->NearDeathBreath;
            if (Player->NearDeatchComponent)
                MaxHP = Player->NearDeatchComponent->BreathMax;
        }
        float barY  = _by2 + 2.0f;
        float barH  = 5.0f;
        float fillW = (MaxHP > 0) ? (CurHP * _bw / MaxHP) : 0.0f;
        draw->AddRectFilled(ImVec2(_bx,barY), ImVec2(_bx2,barY+barH), IM_COL32(0,0,0,160), 2.0f);
        if (fillW > 0.0f)
            draw->AddRectFilled(ImVec2(_bx,barY), ImVec2(_bx+fillW,barY+barH), HPColor, 2.0f);
    }

    // ── Distance ────────────────────────────────────────────────
    if (Config.ESPMenu.Distance) {
        std::string distStr = std::to_string((int)Distance) + "m";
        float baseY   = Config.ESPMenu.Health ? (_by2+2.0f+5.0f+3.0f) : (_by2+3.0f);
        float dFontSz = 11.0f;
        ImVec2 dTSz   = pRegularFont ? pRegularFont->CalcTextSizeA(dFontSz, FLT_MAX, 0.0f, distStr.c_str()) : ImGui::CalcTextSize(distStr.c_str());
        float dPadX = 4.0f, dPadY = 2.0f;
        float dW = dTSz.x + dPadX * 2.0f;
        float dH = dTSz.y + dPadY * 2.0f;
        float dX = _bx + (_bw - dW) * 0.5f;
        draw->AddRectFilled(ImVec2(dX,baseY), ImVec2(dX+dW,baseY+dH), IM_COL32(20,14,0,200), 3.0f);
        draw->AddText(pRegularFont, dFontSz, ImVec2(dX+dPadX,baseY+dPadY), IM_COL32(255,195,40,255), distStr.c_str());
    }

    // ── Weapon ──────────────────────────────────────────────────
    if (Config.ESPMenu.Weapon) {
        std::string weaponLabel = "WEAPON: Unknown";
        if (Player->WeaponManagerComponent) {
            auto* wm = Player->WeaponManagerComponent;
            if (wm->CurrentWeaponReplicated &&
                wm->CurrentWeaponReplicated->IsA(ASTExtraShootWeapon::StaticClass())) {
                auto* sw = (ASTExtraShootWeapon*)wm->CurrentWeaponReplicated;
                std::string wn = sw->GetWeaponName().ToString();
                if (!wn.empty()) weaponLabel = "WEAPON: " + wn;
            }
        }
        float baseY2  = Config.ESPMenu.Health ? (_by2+2.0f+5.0f+3.0f) : (_by2+3.0f);
        float wFontSz = 11.0f;
        ImVec2 wTSz   = pRegularFont ? pRegularFont->CalcTextSizeA(wFontSz, FLT_MAX, 0.0f, weaponLabel.c_str()) : ImGui::CalcTextSize(weaponLabel.c_str());
        float wPadX = 4.0f, wPadY = 2.0f;
        float wW = wTSz.x + wPadX * 2.0f;
        float wH = wTSz.y + wPadY * 2.0f;
        float distRowH = 0.0f;
        if (Config.ESPMenu.Distance) {
            ImVec2 tmp = pRegularFont ? pRegularFont->CalcTextSizeA(wFontSz, FLT_MAX, 0.0f, "0m") : ImGui::CalcTextSize("0m");
            distRowH = tmp.y + 4.0f + 3.0f;
        }
        float wY = baseY2 + distRowH;
        float wX = _bx + (_bw - wW) * 0.5f;
        draw->AddRectFilled(ImVec2(wX,wY), ImVec2(wX+wW,wY+wH), IM_COL32(10,10,10,200), 3.0f);
        draw->AddText(pRegularFont, wFontSz, ImVec2(wX+wPadX,wY+wPadY), IM_COL32(255,255,255,240), weaponLabel.c_str());
    }

}//wsw
  }//actor class
  
  
  
  
if (Config.ESPMenu.LootBox) {
if (Actor->IsA(ASTExtraVehicleBase::StaticClass())) {
    auto Vehicle = (ASTExtraVehicleBase *)Actor;
    if (!Vehicle->Mesh) continue;
    float vDist = Vehicle->GetDistanceTo(localPlayer) / 100.f;
    if (vDist > 400.f) continue;
    FVector vCenter = Vehicle->K2_GetActorLocation();
    std::string vTypeName = "Vehicle";
    {
        std::string vPath = getObjectPath(Vehicle);
        if      (vPath.find("Buggy")   != std::string::npos) vTypeName = "Buggy";
        else if (vPath.find("UAZ")     != std::string::npos) vTypeName = "UAZ";
        else if (vPath.find("Dacia")   != std::string::npos) vTypeName = "Dacia";
        else if (vPath.find("Boat")    != std::string::npos) vTypeName = "Boat";
        else if (vPath.find("Bike")    != std::string::npos) vTypeName = "Motorbike";
        else if (vPath.find("Mirado")  != std::string::npos) vTypeName = "Mirado";
        else if (vPath.find("Truck")   != std::string::npos) vTypeName = "Truck";
        else if (vPath.find("PG117")   != std::string::npos) vTypeName = "PG117";
        else if (vPath.find("Rony")    != std::string::npos) vTypeName = "Rony";
        else if (vPath.find("Scooter") != std::string::npos) vTypeName = "Scooter";
        else if (vPath.find("Tuk")     != std::string::npos) vTypeName = "Tuk-Tuk";
        else if (vPath.find("Heli")    != std::string::npos) vTypeName = "Helicopter";
        else if (vPath.find("Aqua")    != std::string::npos) vTypeName = "Aquarail";
    }
    FVector2D vTopSC;
    FVector vTopWorld = {vCenter.X, vCenter.Y, vCenter.Z + 120.0f};
    if (WorldToScreenBone(vTopWorld, &vTopSC)) {
        std::string vLabel = vTypeName + " [" + std::to_string((int)vDist) + "m]";
        float vFsz = 11.0f;
        ImVec2 vLSz = pRegularFont ? pRegularFont->CalcTextSizeA(vFsz, FLT_MAX, 0.0f, vLabel.c_str()) : ImGui::CalcTextSize(vLabel.c_str());
        float vLX = vTopSC.X - vLSz.x * 0.5f;
        float vLY = vTopSC.Y - vLSz.y - 2.0f;
        draw->AddRectFilled(ImVec2(vLX-3,vLY-1), ImVec2(vLX+vLSz.x+3,vLY+vLSz.y+1), IM_COL32(10,10,10,160), 3.0f);
        draw->AddText(pRegularFont, vFsz, ImVec2(vLX,vLY), IM_COL32(255,215,0,255), vLabel.c_str());
    }
}}
if (Config.ESPMenu.LootBox)
{
if (Actor->IsA(APickUpListWrapperActor::StaticClass()))
{
auto Loot = (APickUpListWrapperActor *)Actor;
auto RootComponent = Actor->RootComponent;
if (!RootComponent)
continue;
float Distance = Loot->GetDistanceTo(localPlayer) / 100.f;
int boxType = static_cast<int>(Loot->BoxType);

FVector2D screen;
if (WorldToScreenBone(Loot->K2_GetActorLocation(), &screen)) {

const char* lootName = GetLootName(Loot);
std::string distanceText = "(" + std::to_string((int)Distance) + "m)";

float fontSize = density / 18.0f;
ImVec2 nameSize = ImGui::CalcTextSize(lootName);
ImVec2 distSize = ImGui::CalcTextSize(distanceText.c_str());

 float nameX = screen.X - nameSize.x / 2.0f;
 float distX = screen.X - distSize.x / 2.0f;

 ImU32 lootColor = GetLootColor(boxType);
draw->AddText(pRegularFont, fontSize, {nameX, screen.Y}, lootColor, lootName);
draw->AddText(pRegularFont, fontSize, {distX, screen.Y + nameSize.y}, IM_COL32_WHITE, distanceText.c_str());
}}}

if (Config.ESPMenu.AirDrop) {
    if (Actor->IsA(AAirDropBoxActor::StaticClass())) {
        auto DropBox = (AAirDropBoxActor *)Actor;
        if (!DropBox->RootComponent) continue;
        float DropDist = DropBox->GetDistanceTo(localPlayer) / 100.f;
        FVector2D DropPos;
        if (WorldToScreenBone(DropBox->K2_GetActorLocation(), &DropPos)) {
            std::string s = "AirDrop [" + std::to_string((int)DropDist) + "m]";
            float aFsz = 11.0f;
            ImVec2 aSz = pRegularFont ? pRegularFont->CalcTextSizeA(aFsz, FLT_MAX, 0.0f, s.c_str()) : ImGui::CalcTextSize(s.c_str());
            float aX = DropPos.X - aSz.x * 0.5f;
            draw->AddRectFilled(ImVec2(aX-3,DropPos.Y-1), ImVec2(aX+aSz.x+3,DropPos.Y+aSz.y+1), IM_COL32(10,10,10,160), 3.0f);
            draw->AddText(pRegularFont, aFsz, ImVec2(aX, DropPos.Y), IM_COL32(255,215,0,255), s.c_str());
        }
    }
}
  
  
if (Config.Unlock120FPS) {
auto objs = UObject::GetGlobalObjects();
for (int i = 0; i < objs.Num(); i++) {
auto Object = objs.GetByIndex(i);
if (isObjectInvalid(Object))
continue;
if (Object->IsA(USTExtraGameInstance::StaticClass())) {
                auto playerChar = (USTExtraGameInstance *) Object;
          playerChar->UserDetailSetting.PUBGDeviceFPSDef = 120;
                playerChar->UserDetailSetting.PUBGDeviceFPSLow = 120;
                playerChar->UserDetailSetting.PUBGDeviceFPSMid = 120;
                playerChar->UserDetailSetting.PUBGDeviceFPSHigh = 120;
                playerChar->UserDetailSetting.PUBGDeviceFPSHDR = 120;
                playerChar->UserDetailSetting.PUBGDeviceFPSUltralHigh = 120;
}
}
if (Config.Nofog) {
auto fogObjs = UObject::GetGlobalObjects();
for (int i = 0; i < fogObjs.Num(); i++) {
auto Object = fogObjs.GetByIndex(i);
if (isObjectInvalid(Object))
continue;
                    UExponentialHeightFogComponent* fogComp = nullptr;
                    if (Object->IsA(UExponentialHeightFogComponent::StaticClass())) {
                        fogComp = (UExponentialHeightFogComponent*)Object;
                    } else if (Object->IsA(AExponentialHeightFog::StaticClass())) {
                        auto fogActor = (AExponentialHeightFog*)Object;
                        if (fogActor) {
                            fogActor->bEnabled = false;
                            fogComp = fogActor->Component;
                        }
                    }

                    if (fogComp) {
                        fogComp->SetFogMaxOpacity(0.0f);
                        fogComp->SetFogDensity(0.0f);
                        fogComp->SetFogCutoffDistance(0.0f);
                        fogComp->SetStartDistance(100000.0f);
                        fogComp->SetVolumetricFog(false);
                        fogComp->SetVolumetricFogExtinctionScale(0.0f);
                        fogComp->SetVolumetricFogDistance(0.0f);
                    }

                    if (Object->IsA(UParticleEmitter::StaticClass())) {
                        auto emitter = (UParticleEmitter *)Object;
                        emitter->EmitterRenderMode = EEmitterRenderMode::ERM_None;
                        emitter->DetailMode = EDetailMode::DM_MAX;
                    }
}
}


}


  
  
  
  
}//actors
}}


 char extra[32];
g_LocalController = localController;
g_LocalPlayer = localPlayer;

// Сбрасываем флаг AutoFeedback при входе в лобби (localPlayer = null)
if (!localPlayer) {
    AutoFeedback_Reset();
}

if (Config.AimBot.Enable && g_LocalController && g_LocalPlayer) {
    EnhancedAimbot();
}
if (totalEnemies > 0 || totalBots > 0) {
char displayText[256];
sprintf(displayText, "Total enemy around you: %d", totalEnemies + totalBots);

float tFontSz = 14.0f;
ImVec2 textSize = pRegularFont
    ? pRegularFont->CalcTextSizeA(tFontSz, FLT_MAX, 0.0f, displayText)
    : ImGui::CalcTextSize(displayText);
float scrW = ImGui::GetIO().DisplaySize.x;
float scrH = ImGui::GetIO().DisplaySize.y;
float tX = (scrW - textSize.x) * 0.5f;
float tY = scrH * 0.09f;
float padX = 8.0f, padY = 4.0f;
ImGui::GetForegroundDrawList()->AddRectFilled(
    ImVec2(tX - padX, tY - padY),
    ImVec2(tX + textSize.x + padX, tY + textSize.y + padY),
    IM_COL32(0, 0, 0, 170), 4.0f);
ImGui::GetForegroundDrawList()->AddText(pRegularFont, tFontSz, ImVec2(tX, tY), IM_COL32(255, 255, 255, 255), displayText);
}



}
 

std::string getClipboardText() {
if (!g_App)
return "";

auto activity = g_App->activity;
if (!activity)
return "";

auto vm = activity->vm;
if (!vm)
return "";

auto object = activity->clazz;
if (!object)
return "";

std::string result;

JNIEnv *env;
vm->AttachCurrentThread(&env, 0);
{
auto ContextClass = env->FindClass("android/content/Context");
auto getSystemServiceMethod = env->GetMethodID(ContextClass, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;");

auto str = env->NewStringUTF("clipboard");
auto clipboardManager = env->CallObjectMethod(object, getSystemServiceMethod, str);
env->DeleteLocalRef(str);

auto ClipboardManagerClass = env->FindClass("android/content/ClipboardManager");
auto getText = env->GetMethodID(ClipboardManagerClass, "getText", "()Ljava/lang/CharSequence;");

auto CharSequenceClass = env->FindClass("java/lang/CharSequence");
auto toStringMethod = env->GetMethodID(CharSequenceClass, "toString", "()Ljava/lang/String;");

auto text = env->CallObjectMethod(clipboardManager, getText);
if (text) {
str = (jstring) env->CallObjectMethod(text, toStringMethod);
result = env->GetStringUTFChars(str, 0);
env->DeleteLocalRef(str);
env->DeleteLocalRef(text);
}

env->DeleteLocalRef(CharSequenceClass);
env->DeleteLocalRef(ClipboardManagerClass);
env->DeleteLocalRef(clipboardManager);
env->DeleteLocalRef(ContextClass);
}
vm->DetachCurrentThread();

return result;
}

const char *GetAndroidID(JNIEnv *env, jobject context) {
jclass contextClass = env->FindClass(/*android/content/Context*/ StrEnc("`L+&0^[S+-:J^$,r9q92(as", "\x01\x22\x4F\x54\x5F\x37\x3F\x7C\x48\x42\x54\x3E\x3B\x4A\x58\x5D\x7A\x1E\x57\x46\x4D\x19\x07", 23).c_str());
jmethodID getContentResolverMethod = env->GetMethodID(contextClass, /*getContentResolver*/ StrEnc("E8X\\7r7ys_Q%JS+L+~", "\x22\x5D\x2C\x1F\x58\x1C\x43\x1C\x1D\x2B\x03\x40\x39\x3C\x47\x3A\x4E\x0C", 18).c_str(), /*()Landroid/content/ContentResolver;*/ StrEnc("8^QKmj< }5D:9q7f.BXkef]A*GYLNg}B!/L", "\x10\x77\x1D\x2A\x03\x0E\x4E\x4F\x14\x51\x6B\x59\x56\x1F\x43\x03\x40\x36\x77\x28\x0A\x08\x29\x24\x44\x33\x0B\x29\x3D\x08\x11\x34\x44\x5D\x77", 35).c_str());
jclass settingSecureClass = env->FindClass(/*android/provider/Settings$Secure*/ StrEnc("T1yw^BCF^af&dB_@Raf}\\FS,zT~L(3Z\"", "\x35\x5F\x1D\x05\x31\x2B\x27\x69\x2E\x13\x09\x50\x0D\x26\x3A\x32\x7D\x32\x03\x09\x28\x2F\x3D\x4B\x09\x70\x2D\x29\x4B\x46\x28\x47", 32).c_str());
jmethodID getStringMethod = env->GetStaticMethodID(settingSecureClass, /*getString*/ StrEnc("e<F*J5c0Y", "\x02\x59\x32\x79\x3E\x47\x0A\x5E\x3E", 9).c_str(), /*(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;*/ StrEnc("$6*%R*!XO\"m18o,0S!*`uI$IW)l_/_knSdlRiO1T`2sH|Ouy__^}%Y)JsQ:-\"(2_^-$i{?H", "\x0C\x7A\x4B\x4B\x36\x58\x4E\x31\x2B\x0D\x0E\x5E\x56\x1B\x49\x5E\x27\x0E\x69\x0F\x1B\x3D\x41\x27\x23\x7B\x09\x2C\x40\x33\x1D\x0B\x21\x5F\x20\x38\x08\x39\x50\x7B\x0C\x53\x1D\x2F\x53\x1C\x01\x0B\x36\x31\x39\x46\x0C\x15\x43\x2B\x05\x30\x15\x41\x43\x46\x55\x70\x0D\x59\x56\x00\x15\x58\x73", 71).c_str());

auto obj = env->CallObjectMethod(context, getContentResolverMethod);
auto str = (jstring) env->CallStaticObjectMethod(settingSecureClass, getStringMethod, obj, env->NewStringUTF(/*android_id*/ StrEnc("ujHO)8OfOE", "\x14\x04\x2C\x3D\x46\x51\x2B\x39\x26\x21", 10).c_str()));
return env->GetStringUTFChars(str, 0);
}

const char *GetDeviceModel(JNIEnv *env) {
jclass buildClass = env->FindClass(/*android/os/Build*/ StrEnc("m5I{GKGWBP-VOxkA", "\x0C\x5B\x2D\x09\x28\x22\x23\x78\x2D\x23\x02\x14\x3A\x11\x07\x25", 16).c_str());
jfieldID modelId = env->GetStaticFieldID(buildClass, /*MODEL*/ StrEnc("|}[q:", "\x31\x32\x1F\x34\x76", 5).c_str(), /*Ljava/lang/String;*/ StrEnc(".D:C:ETZ1O-Ib&^h.Y", "\x62\x2E\x5B\x35\x5B\x6A\x38\x3B\x5F\x28\x02\x1A\x16\x54\x37\x06\x49\x62", 18).c_str());

auto str = (jstring) env->GetStaticObjectField(buildClass, modelId);
return env->GetStringUTFChars(str, 0);
}

const char *GetDeviceBrand(JNIEnv *env) {
jclass buildClass = env->FindClass(/*android/os/Build*/ StrEnc("0iW=2^>0zTRB!B90", "\x51\x07\x33\x4F\x5D\x37\x5A\x1F\x15\x27\x7D\x00\x54\x2B\x55\x54", 16).c_str());
jfieldID modelId = env->GetStaticFieldID(buildClass, /*BRAND*/ StrEnc("@{[FP", "\x02\x29\x1A\x08\x14", 5).c_str(), /*Ljava/lang/String;*/ StrEnc(".D:C:ETZ1O-Ib&^h.Y", "\x62\x2E\x5B\x35\x5B\x6A\x38\x3B\x5F\x28\x02\x1A\x16\x54\x37\x06\x49\x62", 18).c_str());

auto str = (jstring) env->GetStaticObjectField(buildClass, modelId);
return env->GetStringUTFChars(str, 0);
}

const char *GetPackageName(JNIEnv *env, jobject context) {
jclass contextClass = env->FindClass(/*android/content/Context*/ StrEnc("`L+&0^[S+-:J^$,r9q92(as", "\x01\x22\x4F\x54\x5F\x37\x3F\x7C\x48\x42\x54\x3E\x3B\x4A\x58\x5D\x7A\x1E\x57\x46\x4D\x19\x07", 23).c_str());
jmethodID getPackageNameId = env->GetMethodID(contextClass, /*getPackageName*/ StrEnc("YN4DaP)!{wRGN}", "\x3E\x2B\x40\x14\x00\x33\x42\x40\x1C\x12\x1C\x26\x23\x18", 14).c_str(), /*()Ljava/lang/String;*/ StrEnc("VnpibEspM(b]<s#[9cQD", "\x7E\x47\x3C\x03\x03\x33\x12\x5F\x21\x49\x0C\x3A\x13\x20\x57\x29\x50\x0D\x36\x7F", 20).c_str());

auto str = (jstring) env->CallObjectMethod(context, getPackageNameId);
return env->GetStringUTFChars(str, 0);
}

const char *GetDeviceUniqueIdentifier(JNIEnv *env, const char *uuid) {
jclass uuidClass = env->FindClass(/*java/util/UUID*/ StrEnc("B/TxJ=3BZ_]SFx", "\x28\x4E\x22\x19\x65\x48\x47\x2B\x36\x70\x08\x06\x0F\x3C", 14).c_str());

auto len = strlen(uuid);

jbyteArray myJByteArray = env->NewByteArray(len);
env->SetByteArrayRegion(myJByteArray, 0, len, (jbyte *) uuid);

jmethodID nameUUIDFromBytesMethod = env->GetStaticMethodID(uuidClass, /*nameUUIDFromBytes*/ StrEnc("P6LV|'0#A+zQmoat,", "\x3E\x57\x21\x33\x29\x72\x79\x67\x07\x59\x15\x3C\x2F\x16\x15\x11\x5F", 17).c_str(), /*([B)Ljava/util/UUID;*/ StrEnc("sW[\"Q[W3,7@H.vT0) xB", "\x5B\x0C\x19\x0B\x1D\x31\x36\x45\x4D\x18\x35\x3C\x47\x1A\x7B\x65\x7C\x69\x3C\x79", 20).c_str());
jmethodID toStringMethod = env->GetMethodID(uuidClass, /*toString*/ StrEnc("2~5292eW", "\x46\x11\x66\x46\x4B\x5B\x0B\x30", 8).c_str(), /*()Ljava/lang/String;*/ StrEnc("P$BMc' #j?<:myTh_*h0", "\x78\x0D\x0E\x27\x02\x51\x41\x0C\x06\x5E\x52\x5D\x42\x2A\x20\x1A\x36\x44\x0F\x0B", 20).c_str());

auto obj = env->CallStaticObjectMethod(uuidClass, nameUUIDFromBytesMethod, myJByteArray);
auto str = (jstring) env->CallObjectMethod(obj, toStringMethod);
return env->GetStringUTFChars(str, 0);
}

struct MemoryStruct {
char *memory;
size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
size_t realsize = size * nmemb;
struct MemoryStruct *mem = (struct MemoryStruct *) userp;

mem->memory = (char *) realloc(mem->memory, mem->size + realsize + 1);
if (mem->memory == NULL) {
return 0;
}

memcpy(&(mem->memory[mem->size]), contents, realsize);
mem->size += realsize;
mem->memory[mem->size] = 0;

return realsize;
}


std::string Login(const char *user_key) {
if (!g_App)
return "Internal Error";

auto activity = g_App->activity;
if (!activity)
return "Internal Error";

auto vm = activity->vm;
if (!vm)
return "Internal Error";

auto object = activity->clazz;
if (!object)
return "Internal Error";

JNIEnv *env;
vm->AttachCurrentThread(&env, 0);

std::string hwid = user_key;
hwid += GetAndroidID(env, object);
hwid += GetDeviceModel(env);
hwid += GetDeviceBrand(env);

std::string UUID = GetDeviceUniqueIdentifier(env, hwid.c_str());

vm->DetachCurrentThread();

std::string errMsg;

struct MemoryStruct chunk{};
chunk.memory = (char *) malloc(1);
chunk.size = 0;

CURL *curl;
CURLcode res;
curl = curl_easy_init();
//Login
if (curl) {
curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, /*POST*/ StrEnc(",IL=", "\x7C\x06\x1F\x69", 4).c_str());
std::string api_key = ("https://f1.modkey.host/691/connect");
curl_easy_setopt(curl, CURLOPT_URL, (api_key.c_str()));

curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, /*https*/ StrEnc("!mLBO", "\x49\x19\x38\x32\x3C", 5).c_str());
struct curl_slist *headers = NULL;
headers = curl_slist_append(headers, /*Content-Type: application/x-www-form-urlencoded*/ StrEnc("@;Ls\\(KP4Qrop`b#d3094/r1cf<c<=H)AiiBG6i|Ta66s2[", "\x03\x54\x22\x07\x39\x46\x3F\x7D\x60\x28\x02\x0A\x4A\x40\x03\x53\x14\x5F\x59\x5A\x55\x5B\x1B\x5E\x0D\x49\x44\x4E\x4B\x4A\x3F\x04\x27\x06\x1B\x2F\x6A\x43\x1B\x10\x31\x0F\x55\x59\x17\x57\x3F", 47).c_str());
curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
char data[4096];
sprintf(data, /*game=PUBG&user_key=%s&serial=%s*/ StrEnc("qu2yXK,YkJyGD@ut0.u~Nb'5(:.:chK", "\x16\x14\x5F\x1C\x65\x1B\x79\x1B\x2C\x6C\x0C\x34\x21\x32\x2A\x1F\x55\x57\x48\x5B\x3D\x44\x54\x50\x5A\x53\x4F\x56\x5E\x4D\x38", 31).c_str(), user_key, UUID.c_str());
curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &chunk);
curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

res = curl_easy_perform(curl);
if (res == CURLE_OK) {
try {
json result = json::parse(chunk.memory);
if (result[/*status*/ StrEnc("(>_LBm", "\x5B\x4A\x3E\x38\x37\x1E", 6).c_str()] == true) {
std::string token = result[/*data*/ StrEnc("fAVA", "\x02\x20\x22\x20", 4).c_str()][/*token*/ StrEnc("{>3Lr", "\x0F\x51\x58\x29\x1C", 5).c_str()].get<std::string>();


time_t rng = result[/*data*/ StrEnc("fAVA", "\x02\x20\x22\x20", 4).c_str()][/*rng*/ StrEnc("+n,", "\x59\x00\x4B", 3).c_str()].get<time_t>();
//expiredDate = result[/*data*/ StrEnc("fAVA", "\x02\x20\x22\x20", 4).c_str()][/*ts*/ StrEnc("4`", "\x40\x13", 2).c_str()].get<std::string>();
//  modStatus = result[/*data*/ StrEnc("fAVA", "\x02\x20\x22\x20", 4).c_str()][/*ms*/ StrEnc("#e", "\x4E\x16", 2).c_str()].get<std::string>();
if (rng + 30 > time(0)) {
std::string auth = /*PUBG*/ StrEnc("Q*) ", "\x01\x7F\x6B\x67", 4).c_str();;
auth += "-";
auth += user_key;
auth += "-";
auth += UUID;
auth += "-";
auth += /*Vm8Lk7Uj2JmsjCPVPVjrLa7zgfx3uz9E*/ StrEnc("ZD$_K NtaM8Fu=n0fFyO;!Ae<H)*Gy4%", "\x0C\x29\x1C\x13\x20\x17\x1B\x1E\x53\x07\x55\x35\x1F\x7E\x3E\x66\x36\x10\x13\x3D\x77\x40\x76\x1F\x5B\x2E\x51\x19\x32\x03\x0D\x60", 32).c_str();

std::string outputAuth = Tools::CalcMD5(auth);
g_Token = token;
g_Auth = outputAuth;

bValid = g_Token == g_Auth;

}} else {
errMsg = result[/*reason*/ StrEnc("LW(3(c", "\x3E\x32\x49\x40\x47\x0D", 6).c_str()].get<std::string>();
}} catch (json::exception &e) {
errMsg = "{";
errMsg += e.what();
errMsg += "}\n{";
errMsg += chunk.memory;
errMsg += "}";
}} else {
errMsg = curl_easy_strerror(res);
}}
curl_easy_cleanup(curl);
vm->DetachCurrentThread();

return bValid ? "OK" : errMsg;
}

#define IM_CLAMP(V, MN, MX) ((V) < (MN) ? (MN) : (V) > (MX) ? (MX) : (V))
namespace Settings
{
static int Tab = 1;
}
EGLBoolean (*orig_GLThreadSwapBuffers)(EGLDisplay dpy, EGLSurface surface);
EGLBoolean _GLThreadSwapBuffers(EGLDisplay dpy, EGLSurface surface) {
return orig_GLThreadSwapBuffers(dpy, surface);
}

 


void (*orig_onInputEvent)(void *thiz, void *ex_ab, void *ex_ac);
void onInputEvent(void *thiz, void *ex_ab, void *ex_ac) {
orig_onInputEvent(thiz, ex_ab, ex_ac);
if (initImGui)
{
AInputEvent* event = (AInputEvent*)thiz;
if (AInputEvent_getType(event) == AINPUT_EVENT_TYPE_MOTION) {
int32_t action = AMotionEvent_getAction(event);
float x = AMotionEvent_getX(event, 0);
float y = AMotionEvent_getY(event, 0);
 ImGui_SetTouchEvent(action, x, y);
}}
return;
}



int32_t (*orig_ANativeWindow_getWidth)(ANativeWindow *window);
int32_t _ANativeWindow_getWidth(ANativeWindow *window)
{
screenSizeX = orig_ANativeWindow_getWidth(window);
return orig_ANativeWindow_getWidth(window);
}



int32_t (*orig_ANativeWindow_getHeight)(ANativeWindow *window);
int32_t _ANativeWindow_getHeight(ANativeWindow *window)
{
screenSizeY = orig_ANativeWindow_getHeight(window);
return orig_ANativeWindow_getHeight(window);
}



int GetAndroidSdkVersion() {
char prop_value[PROP_VALUE_MAX];
__system_property_get(oxorany("ro.build.version.sdk"), prop_value);
return atoi(prop_value);
}


 


 
// Overlay Thread for AImGui

// ── Texture implementation ───────────────────────────────────
// stbi functions provided by stb_image.cpp
#include "stb_image.h"

static TextureInfo s_textureInfo;

void DrawImage(int x, int y, int w, int h, ImTextureID Texture) {
    ImGui::GetForegroundDrawList()->AddImage(Texture, ImVec2(x, y), ImVec2(x + w, y + h));
}

TextureInfo createTexture(char* ImagePath) {
    int w, h, n;
    stbi_uc* data = stbi_load(ImagePath, &w, &h, &n, 0);
    GLuint texture;
    glGenTextures(1, &texture);
    glEnable(GL_TEXTURE_2D);
    glBindTexture(GL_TEXTURE_2D, texture);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    if (n == 3)
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB, w, h, 0, GL_RGB, GL_UNSIGNED_BYTE, data);
    else
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE, data);
    stbi_image_free(data);
    s_textureInfo.textureId = reinterpret_cast<ImTextureID>((GLuint*)texture);
    s_textureInfo.w = w;
    s_textureInfo.h = h;
    return s_textureInfo;
}

TextureInfo CreateTexture(const unsigned char* buf, int len) {
    TextureInfo image;
    int n = 0;
    unsigned char* image_data = stbi_load_from_memory(buf, len, &image.w, &image.h, &n, 4);
    if (image_data == NULL) { perror("File does not exist"); }
    GLuint image_texture;
    glGenTextures(1, &image_texture);
    glBindTexture(GL_TEXTURE_2D, image_texture);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
#if defined(GL_UNPACK_ROW_LENGTH) && !defined(__EMSCRIPTEN__)
    glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
#endif
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, image.w, image.h, 0, GL_RGBA, GL_UNSIGNED_BYTE, image_data);
    stbi_image_free(image_data);
    image.textureId = (ImTextureID)image_texture;
    return image;
}

// Загружает PNG и инвертирует RGB-каналы (оставляет alpha), делая чёрные иконки белыми
TextureInfo CreateTextureInverted(const unsigned char* buf, int len) {
    TextureInfo image;
    int n = 0;
    unsigned char* image_data = stbi_load_from_memory(buf, len, &image.w, &image.h, &n, 4);
    if (image_data == NULL) { perror("File does not exist"); return image; }
    int pixel_count = image.w * image.h;
    for (int i = 0; i < pixel_count; i++) {
        image_data[i * 4 + 0] = 255 - image_data[i * 4 + 0]; // R
        image_data[i * 4 + 1] = 255 - image_data[i * 4 + 1]; // G
        image_data[i * 4 + 2] = 255 - image_data[i * 4 + 2]; // B
        // alpha [i*4+3] не трогаем
    }
    GLuint image_texture;
    glGenTextures(1, &image_texture);
    glBindTexture(GL_TEXTURE_2D, image_texture);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
#if defined(GL_UNPACK_ROW_LENGTH) && !defined(__EMSCRIPTEN__)
    glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
#endif
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, image.w, image.h, 0, GL_RGBA, GL_UNSIGNED_BYTE, image_data);
    stbi_image_free(image_data);
    image.textureId = (ImTextureID)image_texture;
    return image;
}

TextureInfo Tex_LogoPIC;
TextureInfo Tex_Logo;
TextureInfo Tex_Visual;
TextureInfo Tex_Aim;
TextureInfo Tex_Memory;
TextureInfo Tex_Setting;
TextureInfo Tex_Tian;

void InitTexture() {
    Tex_LogoPIC = CreateTexture(LogoPIC_data, sizeof(LogoPIC_data));
    Tex_Logo    = CreateTexture(Logo_data,    sizeof(Logo_data));
    Tex_Visual  = CreateTextureInverted(Visual_data,  sizeof(Visual_data));
    Tex_Aim     = CreateTextureInverted(Aim_data,     sizeof(Aim_data));
    Tex_Memory  = CreateTextureInverted(Memory_data,  sizeof(Memory_data));
    Tex_Setting = CreateTextureInverted(Setting_data, sizeof(Setting_data));
    Tex_Tian    = CreateTexture(Tian_data,    sizeof(Tian_data));
}

static bool isLogin = false;

void *RunOverlayThread(void *) {
while (!g_App || !g_App->activity) { usleep(100000); }

android::AImGui::Options options;
options.activity = g_App->activity;
options.skipScreenshot = HIDEESP;
android::AImGui overlay(options);

while (items_data.empty()) { usleep(100000); }

bool isInit    = false;
bool texLoaded = false;

static bool g_MenuOpen  = false;
static int  g_Tab       = 0; // 0=Visual 1=Aim 2=Memory 3=Settings
static int  g_AimSub    = 0; // 0=Aimbot 1=SilentAim

// ── Шрифт инициализируется ДО первого BeginFrame ─────────────────
{
    ImGuiIO &io = ImGui::GetIO();
    if (g_App->config) density = AConfiguration_getDensity(g_App->config);
    float fontSize = (float)density / 18.0f;
    if (fontSize < 11.0f) fontSize = 11.0f;

    io.Fonts->Clear();

    ImFontConfig fontCfg;
    fontCfg.FontDataOwnedByAtlas = false;
    static const ImWchar font_ranges[] = {
        0x0020, 0x00FF, // Basic Latin
        0x0400, 0x04FF, // Cyrillic
        0,
    };
    pRegularFont = io.Fonts->AddFontFromMemoryTTF(
        (void*)Jost, (int)sizeof(Jost),
        fontSize, &fontCfg, font_ranges);
    if (!pRegularFont)
        pRegularFont = io.Fonts->AddFontDefault();

    io.Fonts->Build();
}

while (true) {
    overlay.SetSecureMode(HIDEESP);
    overlay.BeginFrame();

    // ── Init ────────────────────────────────────────────────────
    if (!isInit) {
        // Загружаем цвета предметов
        for (auto &i : items_data)
            for (auto &item : i["Items"]) {
                int r,g,b;
                sscanf(item["itemTextColor"].get<std::string>().c_str(),"#%02X%02X%02X",&r,&g,&b);
                ItemColors[item["itemId"].get<int>()] = CREATE_COLOR(r,g,b,255);
            }
        initImGui = true;
        isInit    = true;
    }
    if (isInit && !texLoaded) { InitTexture(); texLoaded = true; }

    ImGuiIO &io = ImGui::GetIO();
    glWidth  = io.DisplaySize.x;
    glHeight = io.DisplaySize.y;
    screenWidth  = glWidth;
    screenHeight = glHeight;

    DrawESP(ImGui::GetBackgroundDrawList());

    // ── Login Screen ─────────────────────────────────────────────
    static std::string g_LoginErr;
    static bool logginIn = false;
    if (!isLogin) {
        // Те же размеры что основное меню
        float mW  = 1000.0f;
        float mH  = 580.0f;
        float mX  = (glWidth  - mW) * 0.5f;
        float mY  = (glHeight - mH) * 0.5f;

        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,    ImVec2(0, 0));
        ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding,   14.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding,    5.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,      ImVec2(8, 10));
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding,     ImVec2(10, 6));

        ImGui::PushStyleColor(ImGuiCol_WindowBg,       ImVec4(0.08f, 0.09f, 0.11f, 0.97f));
        ImGui::PushStyleColor(ImGuiCol_Border,         ImVec4(0.20f, 0.28f, 0.38f, 0.35f));
        ImGui::PushStyleColor(ImGuiCol_FrameBg,        ImVec4(0.11f, 0.14f, 0.18f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(0.16f, 0.26f, 0.38f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_FrameBgActive,  ImVec4(0.22f, 0.36f, 0.52f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_Button,         ImVec4(0.14f, 0.22f, 0.32f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered,  ImVec4(0.22f, 0.38f, 0.52f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,   ImVec4(0.30f, 0.52f, 0.68f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_Text,           ImVec4(0.82f, 0.87f, 0.93f, 1.0f));

        ImGui::SetNextWindowPos(ImVec2(mX, mY), ImGuiCond_Always);
        ImGui::SetNextWindowSize(ImVec2(mW, mH), ImGuiCond_Always);

        if (ImGui::Begin("##login", nullptr,
            ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoScrollbar  | ImGuiWindowFlags_NoSavedSettings |
            ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNav |
            ImGuiWindowFlags_NoScrollWithMouse))
        {
            ImDrawList* ldl  = ImGui::GetWindowDrawList();
            ImVec2      wPos = ImGui::GetWindowPos();

            // Фон
            ldl->AddRectFilled(
                wPos,
                ImVec2(wPos.x + mW, wPos.y + mH),
                IM_COL32(14, 17, 22, 255), 14.0f);

            // Картинка Tian — от левого края, больше половины окна
            float imgW = mW * 0.60f;
            float imgH = mH;
            if (texLoaded && Tex_Tian.textureId) {
                ldl->AddImageRounded(
                    Tex_Tian.textureId,
                    ImVec2(wPos.x, wPos.y),
                    ImVec2(wPos.x + imgW, wPos.y + imgH),
                    ImVec2(0, 0), ImVec2(1, 1),
                    IM_COL32(255, 255, 255, 255),
                    14.0f);
                // Градиент — плавное исчезание фото вправо
                ldl->AddRectFilledMultiColor(
                    ImVec2(wPos.x + imgW * 0.50f, wPos.y),
                    ImVec2(wPos.x + imgW + 1.0f,  wPos.y + imgH),
                    IM_COL32(14, 17, 22, 0),
                    IM_COL32(14, 17, 22, 255),
                    IM_COL32(14, 17, 22, 255),
                    IM_COL32(14, 17, 22, 0));
            }

            // Правая панель поверх фото
            float panelX  = wPos.x + imgW * 0.68f;
            float panelW  = mW - (panelX - wPos.x) - 32.0f;
            float panelCX = panelX + panelW * 0.5f;

            // Заголовок
            {
                const char* title = T("KEY AUTHENTICATION", "АУТЕНТИФИКАЦИЯ");
                float tw = ImGui::CalcTextSize(title).x;
                ImGui::SetCursorScreenPos(ImVec2(panelCX - tw * 0.5f, wPos.y + mH * 0.24f));
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.48f, 0.68f, 0.88f, 1.0f));
                ImGui::Text("%s", title);
                ImGui::PopStyleColor();

                float lineY = wPos.y + mH * 0.24f + ImGui::GetTextLineHeight() + 6.0f;
                ldl->AddLine(
                    ImVec2(panelX, lineY),
                    ImVec2(wPos.x + mW - 32.0f, lineY),
                    IM_COL32(35, 55, 75, 180), 1.0f);
            }

            float formY = wPos.y + mH * 0.36f;

            // Подпись поля
            {
                const char* lbl = T("Enter your license key", "Введите лицензионный ключ");
                float tw = ImGui::CalcTextSize(lbl).x;
                ImGui::SetCursorScreenPos(ImVec2(panelCX - tw * 0.5f, formY));
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.42f, 0.52f, 0.62f, 1.0f));
                ImGui::Text("%s", lbl);
                ImGui::PopStyleColor();
            }

            // Поле ввода
            static char s[64] = {};
            float inputY = formY + ImGui::GetTextLineHeight() + 10.0f;
            ImGui::SetCursorScreenPos(ImVec2(panelX, inputY));
            ImGui::PushItemWidth(panelW);
            ImGui::InputText("##key", s, sizeof s, ImGuiInputTextFlags_Password);
            ImGui::PopItemWidth();

            float btnY = inputY + 38.0f;

            // PASTE
            ImGui::SetCursorScreenPos(ImVec2(panelX, btnY));
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.14f, 0.22f, 0.32f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.22f, 0.38f, 0.52f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.30f, 0.52f, 0.68f, 1.0f));
            if (ImGui::Button(T("PASTE", "ВСТАВИТЬ"), ImVec2(panelW, 36.0f))) {
                auto key = getClipboardText();
                strncpy(s, key.c_str(), sizeof s - 1);
                anticrack = true;
            }
            ImGui::PopStyleColor(3);

            float loginBtnY = btnY + 46.0f;

            // LOGIN — зелёная
            ImGui::SetCursorScreenPos(ImVec2(panelX, loginBtnY));
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.10f, 0.55f, 0.22f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.14f, 0.68f, 0.30f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.08f, 0.42f, 0.18f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_Text,          ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
            if (ImGui::Button(T("LOGIN", "ВОЙТИ"), ImVec2(panelW, 36.0f))) {
                g_LoginErr = Login(s);
                if (g_LoginErr == "OK") {
                    isLogin = bValid && g_Auth == g_Token;
                }
            }
            ImGui::PopStyleColor(4);

            // Ошибка
            if (!g_LoginErr.empty() && g_LoginErr != "OK") {
                float errY = loginBtnY + 46.0f;
                const char* errTxt = T("Error", "Ошибка");
                float tw = ImGui::CalcTextSize(errTxt).x;
                ImGui::SetCursorScreenPos(ImVec2(panelCX - tw * 0.5f, errY));
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.25f, 0.25f, 1.0f));
                ImGui::Text("%s", errTxt);
                ImGui::PopStyleColor();
            }
        }
        ImGui::End();

        ImGui::PopStyleColor(9);
        ImGui::PopStyleVar(6);

        overlay.EndFrame();
        continue;
    }

    // ── Плавающая иконка (drag + анимация) ──────────────────────
    if (!g_MenuOpen) {
        float isz = density * 0.30f;
        if (g_IconX < 0.0f) { g_IconX = glWidth * 0.03f; g_IconY = glHeight * 0.06f; }
        g_IconX = ImClamp(g_IconX, 0.0f, (float)glWidth  - isz);
        g_IconY = ImClamp(g_IconY, 0.0f, (float)glHeight - isz);

        g_IconPulse += ImGui::GetIO().DeltaTime * 1.4f;
        if (g_IconPulse > IM_PI * 2.0f) g_IconPulse -= IM_PI * 2.0f;
        float pulse = sinf(g_IconPulse) * 0.5f + 0.5f;

        ImGui::SetNextWindowPos(ImVec2(0,0), ImGuiCond_Always);
        ImGui::SetNextWindowSize(ImVec2((float)glWidth,(float)glHeight), ImGuiCond_Always);
        ImGui::SetNextWindowBgAlpha(0.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,    ImVec2(0,0));
        ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
        ImGui::Begin("##fi_overlay", nullptr,
            ImGuiWindowFlags_NoDecoration|ImGuiWindowFlags_NoMove|
            ImGuiWindowFlags_NoScrollbar|ImGuiWindowFlags_NoSavedSettings|
            ImGuiWindowFlags_NoBringToFrontOnFocus|ImGuiWindowFlags_NoNav|
            ImGuiWindowFlags_NoBackground|ImGuiWindowFlags_NoInputs);
        ImDrawList* iconDL = ImGui::GetWindowDrawList();

        ImVec2 iconMin(g_IconX, g_IconY), iconMax(g_IconX+isz, g_IconY+isz);
        ImVec2 center(g_IconX+isz*0.5f, g_IconY+isz*0.5f);
        float  radius = isz * 0.5f;
        ImVec2 mp = ImGui::GetIO().MousePos;
        bool   hovered = mp.x>=iconMin.x&&mp.x<=iconMax.x&&mp.y>=iconMin.y&&mp.y<=iconMax.y;
        bool   pressing = ImGui::GetIO().MouseDown[0];

        if (hovered && ImGui::GetIO().MouseClicked[0]) {
            g_IconDragging=true; g_IconDragOffX=mp.x-g_IconX; g_IconDragOffY=mp.y-g_IconY;
        }
        if (g_IconDragging) {
            if (pressing) { g_IconX=mp.x-g_IconDragOffX; g_IconY=mp.y-g_IconDragOffY; }
            else {
                if (fabsf(mp.x-(g_IconDragOffX+g_IconX))<8.f&&fabsf(mp.y-(g_IconDragOffY+g_IconY))<8.f)
                    g_MenuOpen=true;
                g_IconDragging=false;
            }
        }
        float targetScale = hovered ? 1.15f : 1.0f;
        g_IconScale += (targetScale - g_IconScale) * ImGui::GetIO().DeltaTime * 10.0f;
        float hs = isz*g_IconScale*0.5f;
        ImVec2 sMin(center.x-hs, center.y-hs), sMax(center.x+hs, center.y+hs);

        // Серо-голубое кольцо вместо фиолетового
        iconDL->AddCircle(center, radius+6.f+pulse*8.f, IM_COL32(60,130,180,(int)(80*(1.f-pulse))), 48, 2.f);
        iconDL->AddCircle(center, radius+3.f, IM_COL32(50,110,160,120), 48, 1.5f);
        iconDL->AddCircleFilled(center, radius+2.f, IM_COL32(0,0,0,80), 48);
        if (texLoaded && Tex_LogoPIC.textureId)
            iconDL->AddImageRounded(Tex_LogoPIC.textureId, sMin, sMax,
                ImVec2(0,0),ImVec2(1,1), IM_COL32(255,255,255,255), radius*g_IconScale);

        ImGui::End();
        ImGui::PopStyleVar(2);
        Config.AimBot.VisCheck=true; Thundertest=true; anticrack=false;
        overlay.EndFrame(); continue;
    }

    // ── Размеры меню ────────────────────────────────────────────
    float mW  = 1000.0f;
    float mH  = 580.0f;
    float mX  = (glWidth  - mW) * 0.5f;
    float mY  = (glHeight - mH) * 0.5f;
    float sbW = 120.0f;  // шире — больше места для иконок
    float sbH = mH;

    // Лёгкая анимация сайдбара
    g_SideFloat += ImGui::GetIO().DeltaTime * 1.2f;
    if (g_SideFloat > IM_PI * 2.0f) g_SideFloat -= IM_PI * 2.0f;
    float sideOff = sinf(g_SideFloat) * 2.5f;

    // ── Стили ───────────────────────────────────────────────────
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,    ImVec2(0, 0));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding,   18.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding,    8.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,      ImVec2(8, 14));
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding,     ImVec2(10, 6));

    // ── Steel Grey-Blue Theme (полная) ──────────────────────────────
    ImGui::PushStyleColor(ImGuiCol_WindowBg,         ImVec4(0.08f, 0.10f, 0.14f, 0.99f));
    ImGui::PushStyleColor(ImGuiCol_Border,           ImVec4(0.30f, 0.44f, 0.60f, 0.55f));
    ImGui::PushStyleColor(ImGuiCol_FrameBg,          ImVec4(0.11f, 0.15f, 0.20f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_FrameBgHovered,   ImVec4(0.16f, 0.26f, 0.38f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_FrameBgActive,    ImVec4(0.22f, 0.36f, 0.52f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_SliderGrab,       ImVec4(0.30f, 0.58f, 0.85f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_SliderGrabActive, ImVec4(0.45f, 0.74f, 1.00f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_CheckMark,        ImVec4(0.38f, 0.72f, 1.00f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Button,           ImVec4(0.13f, 0.20f, 0.30f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered,    ImVec4(0.20f, 0.36f, 0.54f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,     ImVec4(0.28f, 0.50f, 0.72f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Header,           ImVec4(0.13f, 0.20f, 0.30f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_HeaderHovered,    ImVec4(0.20f, 0.36f, 0.54f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_HeaderActive,     ImVec4(0.28f, 0.50f, 0.72f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_PopupBg,          ImVec4(0.07f, 0.10f, 0.14f, 0.98f));
    ImGui::PushStyleColor(ImGuiCol_Text,             ImVec4(0.86f, 0.91f, 0.97f, 1.0f));

    ImGui::SetNextWindowPos(ImVec2(mX, mY), ImGuiCond_Always);
    ImGui::SetNextWindowSize(ImVec2(mW, mH), ImGuiCond_Always);

    ImGui::Begin("##menu", nullptr,
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoScrollbar  | ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNav |
        ImGuiWindowFlags_NoScrollWithMouse);

    ImDrawList* dl  = ImGui::GetWindowDrawList();
    ImVec2      wPos = ImGui::GetWindowPos();

    // ═══════════════════════════════════════════════════════════════
    // САЙДБАР — чистый тёмный столбец как в референсе
    // ═══════════════════════════════════════════════════════════════
    float sbX = wPos.x;

    // Фон сайдбара — тёмный стальной
    dl->AddRectFilled(
        ImVec2(sbX, wPos.y),
        ImVec2(sbX + sbW, wPos.y + mH),
        IM_COL32(12, 16, 22, 255), 14.0f);

    // Перекрываем скругление справа
    dl->AddRectFilled(
        ImVec2(sbX + sbW * 0.5f, wPos.y),
        ImVec2(sbX + sbW, wPos.y + mH),
        IM_COL32(12, 16, 22, 255));

    // Лёгкий голубой градиент сверху (декор)
    dl->AddRectFilledMultiColor(
        ImVec2(sbX, wPos.y),
        ImVec2(sbX + sbW, wPos.y + mH * 0.45f),
        IM_COL32(30, 80, 130, 35), IM_COL32(30, 80, 130, 35),
        IM_COL32(12, 16, 22, 0),   IM_COL32(12, 16, 22, 0));

    // Правый разделитель — стальной голубой
    dl->AddLine(
        ImVec2(sbX + sbW, wPos.y + 10),
        ImVec2(sbX + sbW, wPos.y + mH - 10),
        IM_COL32(55, 110, 170, 180), 1.2f);

    // Внешний бордер меню — тонкое голубое свечение
    dl->AddRect(
        ImVec2(wPos.x + 1, wPos.y + 1),
        ImVec2(wPos.x + mW - 1, wPos.y + mH - 1),
        IM_COL32(50, 100, 160, 70), 14.0f, 0, 1.5f);

    // ── Логотип ───────────────────────────────────────────────────
    float logSz = 82.0f;
    float logX  = sbX + (sbW - logSz) * 0.5f;
    float logY  = wPos.y + 14.0f;
    if (texLoaded && Tex_Logo.textureId) {
        ImGui::SetCursorScreenPos(ImVec2(logX, logY));
        ImGui::Image(Tex_Logo.textureId, ImVec2(logSz, logSz));
        if (ImGui::IsItemClicked()) g_MenuOpen = false;
    }

    // Разделитель под логотипом — стальной голубой
    dl->AddLine(
        ImVec2(sbX + 12, logY + logSz + 8),
        ImVec2(sbX + sbW - 12, logY + logSz + 8),
        IM_COL32(55, 110, 170, 130), 1.0f);

    // ── Иконки табов — как в референсе ───────────────────────────
    TextureInfo* tabTex[4] = { &Tex_Visual, &Tex_Aim, &Tex_Memory, &Tex_Setting };
    float iSz    = 46.0f;          // иконка крупнее
    float cardW  = sbW - 16.0f;
    float cardH  = iSz + 26.0f;   // карточка выше
    float tabTop = logY + logSz + 18.0f;
    float slotH  = (mH - (tabTop - wPos.y) - 10.0f) / 4.0f;

    const char* tabLabels[4] = {
        T("Visual",   "Визуал"),
        T("Aim",      "Прицел"),
        T("Memory",   "Память"),
        T("Settings", "Настройки")
    };

    for (int t = 0; t < 4; t++) {
        g_TabFloat[t] += ImGui::GetIO().DeltaTime * (0.85f + t * 0.1f);
        if (g_TabFloat[t] > IM_PI * 2.0f) g_TabFloat[t] -= IM_PI * 2.0f;

        float slotCY = tabTop + t * slotH + slotH * 0.5f;
        float cX2    = sbX + 8.0f;
        float cY     = slotCY - cardH * 0.5f;
        float cR     = 10.0f;
        bool  active = (g_Tab == t);

        // Hover-детект
        ImVec2 mp = ImGui::GetIO().MousePos;
        bool hovered = mp.x >= cX2 && mp.x <= cX2 + cardW &&
                       mp.y >= cY  && mp.y <= cY  + cardH;

        // Фон карточки — hover или active
        if (active) {
            // Тень под активной карточкой
            dl->AddRectFilled(
                ImVec2(cX2 + 3, cY + 4),
                ImVec2(cX2 + cardW + 3, cY + cardH + 4),
                IM_COL32(10, 30, 55, 120), cR);
            // Основной фон
            dl->AddRectFilled(
                ImVec2(cX2, cY),
                ImVec2(cX2 + cardW, cY + cardH),
                IM_COL32(18, 44, 76, 255), cR);
            // Внешняя обводка
            dl->AddRect(
                ImVec2(cX2, cY),
                ImVec2(cX2 + cardW, cY + cardH),
                IM_COL32(50, 120, 200, 160), cR, 0, 1.3f);
            // Акцент слева — яркая голубая полоска
            dl->AddRectFilled(
                ImVec2(cX2, cY + 8),
                ImVec2(cX2 + 3, cY + cardH - 8),
                IM_COL32(55, 155, 235, 255), 2.0f);
            // Верхний горизонтальный штрих
            dl->AddRectFilled(
                ImVec2(cX2 + 8, cY),
                ImVec2(cX2 + cardW - 8, cY + 2),
                IM_COL32(55, 155, 235, 140), 1.0f);
        } else if (hovered) {
            dl->AddRectFilled(
                ImVec2(cX2, cY),
                ImVec2(cX2 + cardW, cY + cardH),
                IM_COL32(22, 36, 54, 200), cR);
            dl->AddRect(
                ImVec2(cX2, cY),
                ImVec2(cX2 + cardW, cY + cardH),
                IM_COL32(40, 90, 150, 100), cR, 0, 1.0f);
        }

        // Иконка — смещена вверх чтобы дать место подписи
        float icSz = iSz * 0.85f;
        float icX  = cX2 + (cardW - icSz) * 0.5f;
        float icY2 = cY  + 7.0f;
        if (tabTex[t]->textureId) {
            ImVec4 tint = active
                ? ImVec4(0.45f, 0.78f, 1.00f, 1.0f)
                : (hovered ? ImVec4(0.52f, 0.68f, 0.86f, 0.90f)
                           : ImVec4(0.36f, 0.50f, 0.65f, 0.70f));
            ImGui::SetCursorScreenPos(ImVec2(icX, icY2));
            ImGui::Image(tabTex[t]->textureId, ImVec2(icSz, icSz),
                         ImVec2(0,0), ImVec2(1,1), tint);
            if (ImGui::IsItemClicked()) g_Tab = t;
        }

        // Подпись под иконкой
        float lblFsz = 9.5f;
        ImVec2 lblSz = pRegularFont
            ? pRegularFont->CalcTextSizeA(lblFsz, FLT_MAX, 0.0f, tabLabels[t])
            : ImGui::CalcTextSize(tabLabels[t]);
        float lblX = cX2 + (cardW - lblSz.x) * 0.5f;
        float lblY = icY2 + icSz + 3.0f;
        ImU32 lblCol = active
            ? IM_COL32(120, 185, 255, 255)
            : IM_COL32(80, 110, 145, 180);
        dl->AddText(pRegularFont, lblFsz, ImVec2(lblX, lblY), lblCol, tabLabels[t]);

        // Кликабельная зона по всей карточке
        ImGui::SetCursorScreenPos(ImVec2(cX2, cY));
        ImGui::InvisibleButton(("##tab" + std::to_string(t)).c_str(), ImVec2(cardW, cardH));
        if (ImGui::IsItemClicked()) g_Tab = t;
    }

    // ═══════════════════════════════════════════════════════════════
    // CONTENT AREA — правая часть как в референсе
    // ═══════════════════════════════════════════════════════════════
    
    float cX    = sbW + 1.0f;
    float cW    = mW - sbW - 1.0f;
    float cPadX = 20.0f;
    float cPadY = 14.0f;

    // Фон контентной области — чуть светлее сайдбара
    dl->AddRectFilled(
        ImVec2(wPos.x + sbW, wPos.y),
        ImVec2(wPos.x + mW,  wPos.y + mH),
        IM_COL32(16, 21, 28, 255));

    // Лёгкий голубой градиент сверху контента
    dl->AddRectFilledMultiColor(
        ImVec2(wPos.x + sbW, wPos.y),
        ImVec2(wPos.x + mW,  wPos.y + mH * 0.30f),
        IM_COL32(25, 65, 110, 30), IM_COL32(25, 65, 110, 30),
        IM_COL32(16, 21, 28, 0),   IM_COL32(16, 21, 28, 0));

    // Декоративные уголки — верхний правый
    float cornerSz = 18.0f;
    dl->AddLine(ImVec2(wPos.x + mW - cornerSz, wPos.y + 4),
                ImVec2(wPos.x + mW - 4,        wPos.y + 4),
                IM_COL32(55, 140, 220, 160), 1.5f);
    dl->AddLine(ImVec2(wPos.x + mW - 4, wPos.y + 4),
                ImVec2(wPos.x + mW - 4, wPos.y + cornerSz),
                IM_COL32(55, 140, 220, 160), 1.5f);
    // Нижний правый
    dl->AddLine(ImVec2(wPos.x + mW - cornerSz, wPos.y + mH - 4),
                ImVec2(wPos.x + mW - 4,        wPos.y + mH - 4),
                IM_COL32(55, 140, 220, 100), 1.5f);
    dl->AddLine(ImVec2(wPos.x + mW - 4, wPos.y + mH - 4),
                ImVec2(wPos.x + mW - 4, wPos.y + mH - cornerSz),
                IM_COL32(55, 140, 220, 100), 1.5f);

    // ── Заголовок вкладки (крупный серо-синий текст) ──────────────
    const char* titles[4] = {
        T("Visuals",  "Визуал"),
        T("Aim",      "АимБот"),
        T("Memory",   "Мемори"),
        T("Settings", "Настройки")
    };

    ImGui::SetCursorScreenPos(ImVec2(wPos.x + cX + cPadX, wPos.y + cPadY));
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.65f, 0.82f, 0.98f, 1.0f));
    ImGui::Text("%s", titles[g_Tab]);
    ImGui::PopStyleColor();

    // Горизонтальный разделитель под заголовком — голубой акцент
    float titleBottom = wPos.y + cPadY + ImGui::GetTextLineHeight() + 10.0f;
    dl->AddLine(
        ImVec2(wPos.x + cX + cPadX,  titleBottom),
        ImVec2(wPos.x + mW - cPadX,  titleBottom),
        IM_COL32(45, 100, 165, 180), 1.2f);
    // Короткий яркий штрих в начале линии
    dl->AddLine(
        ImVec2(wPos.x + cX + cPadX,  titleBottom),
        ImVec2(wPos.x + cX + cPadX + 40.0f, titleBottom),
        IM_COL32(80, 160, 240, 255), 2.0f);

    // ── Контент ───────────────────────────────────────────────────
    float contentTop = titleBottom + 12.0f;
    float contentH   = mH - (contentTop - wPos.y) - 8.0f;

    ImGui::SetCursorScreenPos(ImVec2(wPos.x + cX + cPadX, contentTop));
    ImGui::BeginChild("##content", ImVec2(cW - cPadX * 2, contentH), false, 0);

    float halfW    = (cW - cPadX * 2 - 20.0f) * 0.5f;
    float contentW = halfW * 2.0f + 20.0f - 8.0f;  // полная ширина контентной зоны

    // Хелпер: заголовок секции — серый текст + линия справа (как в референсе)
    auto SectionHeader = [&](const char* label) {
        ImVec2 p = ImGui::GetCursorScreenPos();
        ImDrawList* d = ImGui::GetWindowDrawList();
        float lh     = ImGui::GetTextLineHeight();
        float labelW = ImGui::CalcTextSize(label).x;
        float padX   = 10.0f, padY = 3.0f;
        float pillW  = labelW + padX * 2.0f;
        float pillH  = lh + padY * 2.0f;

        // Фоновая пилюля
        d->AddRectFilled(
            ImVec2(p.x, p.y - padY),
            ImVec2(p.x + pillW, p.y + lh + padY),
            IM_COL32(18, 44, 76, 200), pillH * 0.5f);

        // Левый акцент — толстый штрих
        d->AddRectFilled(
            ImVec2(p.x, p.y - padY),
            ImVec2(p.x + 3.0f, p.y + lh + padY),
            IM_COL32(55, 155, 235, 255), 1.5f);

        // Текст
        d->AddText(pRegularFont, ImGui::GetFontSize(),
            ImVec2(p.x + padX, p.y),
            IM_COL32(100, 170, 240, 255), label);
        ImGui::Dummy(ImVec2(pillW, pillH));

        // Горизонтальная линия справа
        float lineY = p.y + lh * 0.5f;
        d->AddLine(
            ImVec2(p.x + pillW + 8.0f, lineY),
            ImVec2(p.x + halfW - 4.0f, lineY),
            IM_COL32(35, 70, 110, 140), 1.0f);
        ImGui::Spacing();
    };

    // ── VISUAL ──────────────────────────────────────────────────────
    if (g_Tab == 0) {
        ImGui::Columns(2, "vis_cols", false);
        ImGui::SetColumnWidth(0, halfW);
        ImGui::SetColumnWidth(1, halfW);

        SectionHeader(T("ESP", "ESP"));
        ImGui::Checkbox(T("Line",        "Линия"),       &Config.ESPMenu.Line);
        ImGui::Checkbox(T("Skeleton",    "Скелет"),      &Config.ESPMenu.Skeleton);
        ImGui::Checkbox(T("Box",         "Бокс"),        &Config.ESPMenu.Box);
        ImGui::Checkbox(T("Name",        "Имя"),         &Config.ESPMenu.Name);
        ImGui::Checkbox(T("Distance",    "Дистанция"),   &Config.ESPMenu.Distance);
        ImGui::Checkbox(T("Health",      "Здоровье"),    &Config.ESPMenu.Health);
        ImGui::Checkbox(T("Target Line", "Линия цели"),  &Config.ESPMenu.TargetLine);
        ImGui::Checkbox(T("Alert",       "Алерт"),        &Config.ESPMenu.ALEART);

        ImGui::NextColumn();

        SectionHeader(T("Extra", "Доп."));
        ImGui::Checkbox(T("Vehicle ESP",   "Транспорт ESP"),  &Config.ESPMenu.LootBox);
        ImGui::Checkbox(T("Loot Items",    "Лут предметы"),   &Config.ESPMenu.LootBoxItems);
        ImGui::Checkbox(T("Off-Screen",    "За экраном"),     &Config.ESPMenu.Offsc);
        ImGui::Checkbox(T("No-Bot Filter", "Без ботов"),      &Config.ESPMenu.NoBot);
        ImGui::Checkbox(T("Weapon",        "Оружие"),         &Config.ESPMenu.Weapon);
        ImGui::Checkbox(T("Air Drop",      "Аирдроп"),        &Config.ESPMenu.AirDrop);

        ImGui::Columns(1);
    }

    // ── AIM ─────────────────────────────────────────────────────────
    if (g_Tab == 1) {
        // Кнопки-сабтабы — на всю ширину, текст по центру
        float fullBW = halfW * 2.0f + 20.0f - 8.0f; // вся ширина контента
        float bW = (fullBW - 6.0f) * 0.5f;
        ImGui::PushStyleVar(ImGuiStyleVar_ButtonTextAlign, ImVec2(0.5f, 0.5f));
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 10.0f);
        auto subBtn = [&](int idx, const char* lbl) {
            bool sel = (g_AimSub == idx);
            ImGui::PushStyleColor(ImGuiCol_Button,
                sel ? ImVec4(0.16f, 0.38f, 0.62f, 1.0f)
                    : ImVec4(0.10f, 0.14f, 0.20f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
                sel ? ImVec4(0.22f, 0.46f, 0.72f, 1.0f)
                    : ImVec4(0.14f, 0.22f, 0.34f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_Text,
                sel ? ImVec4(0.75f, 0.92f, 1.0f, 1.0f)
                    : ImVec4(0.44f, 0.56f, 0.70f, 1.0f));
            if (ImGui::Button(lbl, ImVec2(bW, 34.0f))) g_AimSub = idx;
            ImGui::PopStyleColor(3);
        };
        subBtn(0, T("Aimbot",     "Аимбот"));
        ImGui::SameLine(0, 6);
        subBtn(1, T("Silent Aim", "Тихий прицел"));
        ImGui::PopStyleVar(2); // ButtonTextAlign + FrameRounding
        ImGui::Spacing();
        ImGui::Spacing();

        if (g_AimSub == 0) {
            // Combo массивы — динамически по языку
            const char* abI_en[] = { "FOV", "Distance" };
            const char* abI_ru[] = { "ФОВ", "Дистанция" };
            const char** abI = g_LangRU ? abI_ru : abI_en;

            const char* trI_en[] = { "None", "Shooting", "Scoping", "Both", "Any" };
            const char* trI_ru[] = { "Нет", "Стрельба", "Прицел", "Оба", "Любой" };
            const char** trI = g_LangRU ? trI_ru : trI_en;

            const char* tgI_en[] = { "Head", "Neck", "Chest", "Pelvis" };
            const char* tgI_ru[] = { "Голова", "Шея", "Грудь", "Таз" };
            const char** tgI = g_LangRU ? tgI_ru : tgI_en;

            ImGui::Columns(2, "aim_cols", false);
            ImGui::SetColumnWidth(0, halfW);
            ImGui::SetColumnWidth(1, halfW);

            SectionHeader(T("General",  "Общее"));
            ImGui::Checkbox(T("Enable Aimbot", "Включить аимбот"), &Config.AimBot.Enable);
            ImGui::Spacing();
            SectionHeader(T("Settings", "Настройки"));
            ImGui::SliderFloat(T("FOV",      "ФОВ"),       &Config.AimBot.FOV,     0, 300, "%.0f");
            ImGui::SliderFloat(T("Distance", "Дистанция"), &Config.AimBot.AimDist, 0, 250, "%.0f");
            ImGui::SliderFloat(T("Smooth",   "Плавность"), &Config.AimBot.Smooth,  1, 10.0f, "%.1f");
            ImGui::SliderFloat(T("Recoil",   "Отдача"),    &Config.AimBot.Recc,    1, 10.0f, "%.2f");
            ImGui::Combo(T("Aim By", "Метод"), &Config.AimBot.AimBy, abI, 2);

            ImGui::NextColumn();

            SectionHeader(T("Selection", "Выбор"));
            ImGui::Combo(T("Trigger", "Триггер"), &Config.AimBot.Trigger, trI, 5);
            ImGui::Combo(T("Target",  "Цель"),    &Config.AimBot.Target,  tgI, 4);
            ImGui::Spacing();
            SectionHeader(T("Options", "Опции"));
            ImGui::Checkbox(T("Prediction",     "Предсказание"),    &Config.AimBot.Pred);
            ImGui::Checkbox(T("Vis Check",      "Проверка видимости"), &Config.AimBot.VisCheck);
            ImGui::Checkbox(T("Ignore Knocked", "Игнор нокаут"),    &Config.AimBot.IgnoreKnocked);
            ImGui::Checkbox(T("Ignore Bots",    "Игнор ботов"),     &Config.AimBot.IgnoreBot);

            ImGui::Columns(1);
        } else {
            const char* bon_en[] = { "Head", "Neck", "Chest", "Pelvis", "Random" };
            const char* bon_ru[] = { "Голова", "Шея", "Грудь", "Таз", "Случайно" };
            const char** bon = g_LangRU ? bon_ru : bon_en;

            const char* trg_en[] = { "Always", "Shooting", "Scoping", "Shoot/Scope" };
            const char* trg_ru[] = { "Всегда", "Стрельба", "Прицел", "Стрел/Прицел" };
            const char** trg = g_LangRU ? trg_ru : trg_en;

            ImGui::Columns(2, "sa_cols", false);
            ImGui::SetColumnWidth(0, halfW);
            ImGui::SetColumnWidth(1, halfW);

            SectionHeader(T("General",  "Общее"));
            ImGui::Checkbox(T("Active",          "Активен"),         &Config.SilentAim.Enable);
            ImGui::Checkbox(T("Ignore Knocked",  "Игнор нокаут"),    &Config.SilentAim.IgnoreKnocked);
            ImGui::Checkbox(T("Vehicle Predict", "Предск. машины"),  &Config.SilentAim.VehiclePrediction);
            ImGui::Spacing();
            SectionHeader(T("Settings", "Настройки"));
            ImGui::SliderFloat(T("FOV",      "ФОВ"),       &Config.SilentAim.FOV,        0, 300, "%.0f");
            ImGui::SliderFloat(T("Distance", "Дистанция"), &Config.SilentAim.MaxDistance, 0, 200, "%.0f m");

            ImGui::NextColumn();

            SectionHeader(T("Selection", "Выбор"));
            ImGui::Combo(T("Bone",    "Кость"),   &Config.SilentAim.TargetBone, bon, 5);
            ImGui::Combo(T("Trigger", "Триггер"), &Config.SilentAim.Trigger,    trg, 4);
            ImGui::Spacing();
            SectionHeader(T("Options", "Опции"));
            ImGui::Checkbox(T("Visible Check",   "Проверка видимости"), &Config.SilentAim.VisibleCheck);
            ImGui::Checkbox(T("Ignore Bot",      "Игнор ботов"),        &Config.SilentAim.IgnoreBot);
            ImGui::Checkbox(T("Fake Damage Fix", "Фикс урона"),         &Config.SilentAim.FakeDamage);

            ImGui::Columns(1);
        }
    }

    // ── MEMORY ──────────────────────────────────────────────────────
    if (g_Tab == 2) {
        SectionHeader(T("General", "Общее"));
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.40f, 0.50f, 0.60f, 1.0f));
        
        ImGui::Checkbox(T("No fog", "Нет радиации"),         &Config.Nofog);
        ImGui::Checkbox(T("120 FPS", "120 ФПС анлок"),         &Config.Unlock120FPS);
        ImGui::PopStyleColor();
    }

    // ── SETTINGS ────────────────────────────────────────────────────
    if (g_Tab == 3) {
        // ── Language toggle ─────────────────────────────────────────
        SectionHeader(T("Language", "Язык"));
        ImGui::Spacing();

        // Button label: shows the OPPOSITE language (what you switch TO)
        const char* langBtnLabel = g_LangRU ? "ENG" : "RU";
        // Color: blue-ish for ENG, red-ish for RU
        ImVec4 langCol  = g_LangRU
            ? ImVec4(0.18f, 0.42f, 0.72f, 1.0f)   // ENG = blue
            : ImVec4(0.72f, 0.16f, 0.16f, 1.0f);  // RU  = red
        ImVec4 langHov  = ImVec4(langCol.x + 0.1f, langCol.y + 0.1f, langCol.z + 0.1f, 1.0f);
        ImVec4 langAct  = ImVec4(langCol.x - 0.1f, langCol.y - 0.1f, langCol.z - 0.1f, 1.0f);

        ImGui::PushStyleColor(ImGuiCol_Button,        langCol);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, langHov);
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,  langAct);
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 10.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding,  ImVec2(14, 10));
        ImGui::SetNextItemWidth(contentW);
        // Big button spanning full content width, 48px tall
        if (ImGui::Button(langBtnLabel, ImVec2(contentW, 48.0f))) {
            g_LangRU = !g_LangRU;
        }
        ImGui::PopStyleVar(2);
        ImGui::PopStyleColor(3);

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // ── General ─────────────────────────────────────────────────
        SectionHeader(T("General", "Основные"));
        ImGui::Checkbox(T("Hide Record Hack", "Скрыть запись хака"), &HIDEESP);

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // ── Config system ────────────────────────────────────────────
        SectionHeader(T("Config", "Конфиг"));
        ImGui::Spacing();

        float btnW = (contentW - 8.0f) * 0.5f;

        // Save CFG button — зелёный с скруглением
        ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.10f, 0.42f, 0.20f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.15f, 0.58f, 0.28f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.08f, 0.32f, 0.15f, 1.0f));
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 10.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12, 8));
        if (ImGui::Button(T("  Save CFG", "  Сохранить"), ImVec2(btnW, 44.0f))) {
            SaveConfig();
            g_CfgMsg  = T("Config saved!", "Конфиг сохранён!");
            g_CfgMsgT = 2.5f;
        }
        ImGui::PopStyleVar(2);
        ImGui::PopStyleColor(3);

        ImGui::SameLine(0, 8.0f);

        // Load CFG button — голубой с скруглением
        ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.12f, 0.28f, 0.52f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.18f, 0.40f, 0.70f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.08f, 0.20f, 0.40f, 1.0f));
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 10.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12, 8));
        if (ImGui::Button(T("  Load CFG", "  Загрузить"), ImVec2(btnW, 44.0f))) {
            if (LoadConfig()) {
                g_CfgMsg  = T("Config loaded!", "Конфиг загружен!");
            } else {
                g_CfgMsg  = T("No config found!", "Файл не найден!");
            }
            g_CfgMsgT = 2.5f;
        }
        ImGui::PopStyleVar(2);
        ImGui::PopStyleColor(3);

        // Status message with fade
        if (g_CfgMsgT > 0.0f) {
            g_CfgMsgT -= ImGui::GetIO().DeltaTime;
            float alpha = std::min(1.0f, g_CfgMsgT);
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 0.95f, 0.55f, alpha));
            ImGui::Spacing();
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (contentW - ImGui::CalcTextSize(g_CfgMsg.c_str()).x) * 0.5f);
            ImGui::TextUnformatted(g_CfgMsg.c_str());
            ImGui::PopStyleColor();
        }

        ImGui::Spacing();
        // CFG file path hint
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.35f, 0.45f, 0.55f, 1.0f));
        ImGui::TextWrapped("%s", CFG_PATH);
        ImGui::PopStyleColor();

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // ── AutoFeedback Send button ─────────────────────────────────
        SectionHeader(T("Feedback", "Отправить"));
        ImGui::Spacing();

        // Send Feedback button — оранжевый
        ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.72f, 0.36f, 0.12f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.86f, 0.48f, 0.20f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.55f, 0.25f, 0.08f, 1.0f));
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 10.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12, 8));
        if (ImGui::Button(T("  Send AutoFeedback", "  Отправить АвтоОтзыв"), ImVec2(contentW, 44.0f))) {
            if (g_LocalPlayer) {
                ManualFeedback_Send(g_LocalPlayer);
                g_FeedbackBtnMsg = T("Feedback sent!", "Отзыв отправлен!");
                g_FeedbackBtnMsgT = 2.5f;
            } else {
                g_FeedbackBtnMsg = T("No player data!", "Нет данных игрока!");
                g_FeedbackBtnMsgT = 2.5f;
            }
        }
        ImGui::PopStyleVar(2);
        ImGui::PopStyleColor(3);

        // Feedback status message with fade
        if (g_FeedbackBtnMsgT > 0.0f) {
            g_FeedbackBtnMsgT -= ImGui::GetIO().DeltaTime;
            float alpha = std::min(1.0f, g_FeedbackBtnMsgT);
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.65f, 0.25f, alpha));
            ImGui::Spacing();
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (contentW - ImGui::CalcTextSize(g_FeedbackBtnMsg.c_str()).x) * 0.5f);
            ImGui::TextUnformatted(g_FeedbackBtnMsg.c_str());
            ImGui::PopStyleColor();
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // ── Skin button ──────────────────────────────────────────────
        SectionHeader(T("Skin", "Скин"));
        ImGui::Spacing();

        ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.45f, 0.10f, 0.55f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.60f, 0.18f, 0.72f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.32f, 0.07f, 0.40f, 1.0f));
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 10.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12, 8));
        if (ImGui::Button(T("  Skin", "  Скин"), ImVec2(contentW, 44.0f))) {
            g_SkinOpen = true;
        }
        ImGui::PopStyleVar(2);
        ImGui::PopStyleColor(3);

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // ── Feedback ─────────────────────────────────────────────────
        SectionHeader(T("Feedback", "Отзыв"));
        ImGui::Spacing();

        ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.10f, 0.38f, 0.58f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.16f, 0.52f, 0.76f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.07f, 0.28f, 0.44f, 1.0f));
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 10.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding,  ImVec2(12, 8));
        if (ImGui::Button(T("  Send Feedback", "  Отправить отзыв"), ImVec2(contentW, 44.0f))) {
            ManualFeedback_Send(g_LocalPlayer);
            g_FeedbackBtnMsg  = T("Sending...", "Отправка...");
            g_FeedbackBtnMsgT = 3.0f;
        }
        ImGui::PopStyleVar(2);
        ImGui::PopStyleColor(3);

        // Статус с fade
        if (g_FeedbackBtnMsgT > 0.0f) {
            g_FeedbackBtnMsgT -= ImGui::GetIO().DeltaTime;
            float alpha = std::min(1.0f, g_FeedbackBtnMsgT);
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 0.85f, 1.0f, alpha));
            ImGui::Spacing();
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() +
                (contentW - ImGui::CalcTextSize(g_FeedbackBtnMsg.c_str()).x) * 0.5f);
            ImGui::TextUnformatted(g_FeedbackBtnMsg.c_str());
            ImGui::PopStyleColor();
        }
    }

    ImGui::EndChild();
    ImGui::End();

    // ── SKIN WINDOW ──────────────────────────────────────────────────
    if (g_SkinOpen) {
        // Same size and position as main window
        ImGui::SetNextWindowSize(ImVec2(mW, mH), ImGuiCond_Always);
        ImGui::SetNextWindowPos(ImVec2(mX, mY), ImGuiCond_Always);

        ImGui::PushStyleColor(ImGuiCol_WindowBg,   ImVec4(0.06f, 0.07f, 0.09f, 0.97f));
        ImGui::PushStyleColor(ImGuiCol_Border,     ImVec4(0.20f, 0.20f, 0.28f, 1.0f));
        ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 14.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));

        ImGui::Begin("##SkinWindow", nullptr,
            ImGuiWindowFlags_NoTitleBar |
            ImGuiWindowFlags_NoResize   |
            ImGuiWindowFlags_NoMove     |
            ImGuiWindowFlags_NoScrollbar|
            ImGuiWindowFlags_NoScrollWithMouse);

        // ── Close button (X) in top-right corner ─────────────────────
        ImVec2 winPos  = ImGui::GetWindowPos();
        ImVec2 winSize = ImGui::GetWindowSize();

        float  btnSz   = 32.0f;
        float  margin  = 10.0f;
        ImVec2 btnPos  = ImVec2(winPos.x + winSize.x - btnSz - margin, winPos.y + margin);

        ImGui::SetCursorPos(ImVec2(winSize.x - btnSz - margin, margin));

        ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.55f, 0.10f, 0.10f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.80f, 0.15f, 0.15f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.40f, 0.07f, 0.07f, 1.0f));
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 0));

        if (ImGui::Button("X##SkinClose", ImVec2(btnSz, btnSz))) {
            g_SkinOpen = false;
        }

        ImGui::PopStyleVar(2);
        ImGui::PopStyleColor(3);

        // ── Content ───────────────────────────────────────────────────
        ImGui::SetCursorPos(ImVec2(20, 55));
        ImGui::BeginChild("##SkinContent", ImVec2(mW - 40, mH - 65), false);

        // ── Skin enable toggles ──────────────────────────────────────
        ImGui::Checkbox(T("Enable Skin Hack", "Включить скин хак"), &skin.bEnable);
        ImGui::SameLine();
        ImGui::Checkbox(T("Gun Skin",    "Скин оружия"),   &skin.bGunSkin);
        ImGui::SameLine();
        ImGui::Checkbox(T("Cloth Skin",  "Скин одежды"),   &skin.bClothSkin);
        ImGui::SameLine();
        ImGui::Checkbox(T("Vehicle",     "Транспорт"),     &skin.bVehicleSkin);
        ImGui::SameLine();
        ImGui::Checkbox(T("Kill Msg",    "Сообщение смерти"), &skin.bKillMsg);
        ImGui::SameLine();
        ImGui::Checkbox(T("Dead Box",    "Дедбокс"),       &skin.bDeadbox);

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if (ImGui::BeginTable("##skintable", 3,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
            ImVec2(mW - 40, mH - 130)))
        {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn(T("Selector", "Выбор"),    ImGuiTableColumnFlags_WidthFixed, 130.0f);
            ImGui::TableSetupColumn(T("Item",     "Предмет"),  ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn(T("Custom ID","Свой ID"),  ImGuiTableColumnFlags_WidthFixed, 90.0f);
            ImGui::TableHeadersRow();

            // ── Guns ─────────────────────────────────────────────────────
            ImGui::TableNextRow(); ImGui::TableSetColumnIndex(1);
            ImGui::TextColored(ImVec4(0.4f,0.8f,1.0f,1.0f), T("── Assault Rifles ──", "── Штурмовые ──"));

            RenderSkinItem("M416",   skindata.m416);
            RenderSkinItem("AKM",    skindata.akm);
            RenderSkinItem("SCAR-L", skindata.scarl);
            RenderSkinItem("M16A4",  skindata.m16);
            RenderSkinItem("AUG",    skindata.aug);
            RenderSkinItem("M762",   skindata.m762);
            RenderSkinItem("GROZA",  skindata.groza);
            RenderSkinItem("ACE32",  skindata.ace32);
            RenderSkinItem("QBZ",    skindata.qbz);
            RenderSkinItem("Honey Badger", skindata.honey);

            ImGui::TableNextRow(); ImGui::TableSetColumnIndex(1);
            ImGui::TextColored(ImVec4(0.4f,0.8f,1.0f,1.0f), T("── SMG ──", "── ПП ──"));

            RenderSkinItem("UMP45",    skindata.ump45);
            RenderSkinItem("UZI",      skindata.uzi);
            RenderSkinItem("Vector",   skindata.vector);
            RenderSkinItem("Tommy",    skindata.tommy);
            RenderSkinItem("PP-19",    skindata.pp19);

            ImGui::TableNextRow(); ImGui::TableSetColumnIndex(1);
            ImGui::TextColored(ImVec4(0.4f,0.8f,1.0f,1.0f), T("── Snipers ──", "── Снайперки ──"));

            RenderSkinItem("Kar98K",  skindata.kar98);
            RenderSkinItem("M24",     skindata.m24);
            RenderSkinItem("AWM",     skindata.awm);
            RenderSkinItem("AMR",     skindata.amr);
            RenderSkinItem("Mk14",    skindata.mk14);
            RenderSkinItem("Mini14",  skindata.mini14);

            ImGui::TableNextRow(); ImGui::TableSetColumnIndex(1);
            ImGui::TextColored(ImVec4(0.4f,0.8f,1.0f,1.0f), T("── LMG ──", "── Пулемёты ──"));

            RenderSkinItem("M249",  skindata.m249);
            RenderSkinItem("DP-28", skindata.dp28);
            RenderSkinItem("MG3",   skindata.mg3);

            ImGui::TableNextRow(); ImGui::TableSetColumnIndex(1);
            ImGui::TextColored(ImVec4(0.4f,0.8f,1.0f,1.0f), T("── Shotguns ──", "── Дробовики ──"));

            RenderSkinItem("S12K",   skindata.s12k);
            RenderSkinItem("DBS",    skindata.dbs);
            RenderSkinItem("XM1014", skindata.xm1014);

            ImGui::TableNextRow(); ImGui::TableSetColumnIndex(1);
            ImGui::TextColored(ImVec4(0.4f,0.8f,1.0f,1.0f), T("── Melee ──", "── Ближний бой ──"));

            RenderSkinItem("Pan",   skindata.pan);
            RenderSkinItem("Knife", skindata.knife);
            RenderSkinItem("Knife1",skindata.knife1);

            // ── Clothes ──────────────────────────────────────────────────
            ImGui::TableNextRow(); ImGui::TableSetColumnIndex(1);
            ImGui::TextColored(ImVec4(0.4f,1.0f,0.6f,1.0f), T("── Clothes ──", "── Одежда ──"));

            RenderSkinItem(T("Shirt",     "Рубашка"),  skindata.cloth);
            RenderSkinItem(T("Hat",       "Шапка"),    skindata.hat);
            RenderSkinItem(T("Pants",     "Штаны"),    skindata.pant);
            RenderSkinItem(T("Shoes",     "Обувь"),    skindata.shoe);
            RenderSkinItem(T("Parachute", "Парашют"),  skindata.parachute);
            RenderSkinItem(T("Glider",    "Глайдер"),  skindata.glider);
            RenderSkinItem(T("Backpack 1","Рюкзак 1"), skindata.backpack1);
            RenderSkinItem(T("Backpack 2","Рюкзак 2"), skindata.backpack2);
            RenderSkinItem(T("Backpack 3","Рюкзак 3"), skindata.backpack3);
            RenderSkinItem(T("Helmet 1",  "Шлем 1"),   skindata.helmet1);
            RenderSkinItem(T("Helmet 2",  "Шлем 2"),   skindata.helmet2);
            RenderSkinItem(T("Helmet 3",  "Шлем 3"),   skindata.helmet3);

            // ── Vehicles ─────────────────────────────────────────────────
            ImGui::TableNextRow(); ImGui::TableSetColumnIndex(1);
            ImGui::TextColored(ImVec4(1.0f,0.8f,0.3f,1.0f), T("── Vehicles ──", "── Транспорт ──"));

            RenderSkinItem("UAZ",    skindata.uaz);
            RenderSkinItem("Dacia",  skindata.dacia);
            RenderSkinItem("Mirado", skindata.mirado);
            RenderSkinItem("Motor",  skindata.motor);
            RenderSkinItem("Buggy",  skindata.buggy);
            RenderSkinItem("Coupe",  skindata.coupe);

            ImGui::EndTable();
        }

        ImGui::EndChild();

        ImGui::End();

        ImGui::PopStyleVar(3);
        ImGui::PopStyleColor(2);
    }
    // ─────────────────────────────────────────────────────────────────

    ImGui::PopStyleColor(16);
    ImGui::PopStyleVar(6);

    Config.AimBot.VisCheck = true;
    Thundertest = true;
    anticrack   = false;

    overlay.EndFrame();
}
}



__int64 (*osub_1D081C)(__int64 a1, __int64 a2, __int64 a3, __int64 a4) = 0;

__int64 __fastcall hsub_1D081C(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
    return 0;
}

int64_t sub_6AF7F5C(int64_t a1, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t) {
    if (a1) {
        *reinterpret_cast<uint8_t*>(a1 + 484) = 1;
        *reinterpret_cast<uint8_t*>(a1 + 485) = 0;
        *reinterpret_cast<uint8_t*>(a1 + 486) = 1;
    }
    return 0LL;
}



int64_t (*oorig_verturi)(int a1, void* a2, size_t a3) = nullptr;

int64_t hsyscall_verturi(int a1, void* a2, size_t a3) {
    LOGI("[SYS] Hooked syscall: arg1=%d, buf=%p, size=%zu", a1, a2, a3);
    if (a2 != nullptr && a3 > 0)
        memset(a2, 0, a3);
    return oorig_verturi(a1, a2, a3);
}

// ── SkinMain.h (inlined) ─────────────────────────────────────────────────────

bool UpdateClothSkin(UCharacterAvatarComponent2*);

ASTExtraVehicleBase* lastVehicle = nullptr;
bool isModded = false, isLoggedIn = false;
static DWORD Last_Gun_Used_To_Kill = 0, Current_Weapon = 0;
static std::string package_name = "";

int ReceiveDrawHUD_Index = -1, OnRep_AvatarMeshChanged_Index = -1, OnRep_BodySlotStateChanged_Index = -1;
int GetItemAvatarHandle_Index = -1, CreateBattleItemHandle_Index = -1, CreateWeaponAndChangeSkin_Index = -1;
int DeadBoxAvatarComponent_Index = -1, DeadBoxAvatarComponent_GetLuaFilePath_Index = -1;

int GetWeap(int w) {
    static const std::unordered_map<int, int> weaponMap = {
        {ID_AKM, skin.gun->AKM}, {ID_M16A4, skin.gun->M16A4}, {ID_SCARL, skin.gun->SCARL}, {ID_M416, skin.gun->M416},
        {ID_AUG, skin.gun->AUG}, {ID_ACE32, skin.gun->ACE32}, {ID_M762, skin.gun->M762}, {ID_QBZ, skin.gun->QBZ},
        {ID_GROZA, skin.gun->GROZA}, {ID_HONEY_BADGER, skin.gun->HONEY}, {ID_UMP45, skin.gun->UMP45},
        {ID_VECTOR, skin.gun->VECTOR}, {ID_THOMPSON, skin.gun->TOMMY}, {ID_UZI, skin.gun->UZI}, {ID_PP19, skin.gun->PP19},
        {ID_AWM, skin.gun->AWM}, {ID_AMR, skin.gun->AMR}, {ID_M24, skin.gun->M24}, {ID_KAR98K, skin.gun->KAR98},
        {ID_MK14, skin.gun->MK14}, {ID_MINI14, skin.gun->MINI14}, {ID_M249, skin.gun->M249}, {ID_DP28, skin.gun->DP28},
        {ID_PAN, skin.gun->PAN}, {ID_M1014, skin.gun->XM1014}, {ID_DBS, skin.gun->DBS}, {ID_S12K, skin.gun->S12K},
        {ID_MG3, skin.gun->MG3}, {ID_P90, skin.gun->P90}
    };
    return weaponMap.count(w) ? weaponMap.at(w) : 0;
}

struct Gun {
    DWORD GUN, flash, compe, silent, quickmag, extmag, quickextmag, canced, reddot, holo, X2, X3, X4, X6, X8,
          vertical, angle, light, pink, lazer, thumb, stock, pak, bullet;

    void ChangeSkin(ASTExtraWeapon* gun) {
        auto data = gun->synData;
        if (data.Num() < 6 || data[7].DefineID.TypeSpecificID <= 0) return;

        data[7].DefineID.TypeSpecificID = GUN;

        auto updateAttachment = [&](int index, DWORD value, const std::vector<int>& validIds) {
            if (value > 0 && data[index].DefineID.TypeSpecificID > 0 &&
                std::find(validIds.begin(), validIds.end(), data[index].DefineID.TypeSpecificID) != validIds.end()) {
                data[index].DefineID.TypeSpecificID = value;
            }
        };

        updateAttachment(0, flash,       {201010, 201005, 201004});
        updateAttachment(0, compe,       {201009, 201003, 201002});
        updateAttachment(0, silent,      {201011, 201007, 201006});
        updateAttachment(4, canced,      {203018});
        updateAttachment(4, reddot,      {203001});
        updateAttachment(4, holo,        {203002});
        updateAttachment(4, X2,          {203003});
        updateAttachment(4, X3,          {203014});
        updateAttachment(4, X4,          {203004});
        updateAttachment(4, X6,          {203015});
        updateAttachment(4, X8,          {203005});
        updateAttachment(2, quickmag,    {204012, 204005, 204008});
        updateAttachment(2, extmag,      {204011, 204004, 204007});
        updateAttachment(2, quickextmag, {204013, 204006, 204009});
        updateAttachment(1, vertical,    {202002});
        updateAttachment(1, angle,       {202001});
        updateAttachment(1, light,       {202004});
        updateAttachment(1, pink,        {202005});
        updateAttachment(1, lazer,       {202007});
        updateAttachment(1, thumb,       {202006});
        if (stock > 0 && data[3].DefineID.TypeSpecificID > 0) data[3].DefineID.TypeSpecificID = stock;
        updateAttachment(5, pak,         {205003});
        updateAttachment(5, bullet,      {204014});
    }

    std::string ToString() {
        char a[512];
        sprintf(a, "GUN: %d, flash: %d, compe: %d, silent: %d, quick: %d, extmag: %d, quickextmag: %d, canced: %d, reddot: %d, holo: %d, X2: %d, X3: %d, X4: %d, X6: %d, X8: %d, vertical: %d, angel: %d, light: %d, pink: %d, lazer: %d, thumb: %d, stock: %d, pak: %d, bullet: %d",
                GUN, flash, compe, silent, quickmag, extmag, quickextmag, canced, reddot, holo, X2, X3, X4, X6, X8, vertical, angle, light, pink, lazer, thumb, stock, pak, bullet);
        return std::string(a);
    }
};

Gun GetFullWeapon(DWORD id) {
    static const std::unordered_map<DWORD, Gun> skinMap = {
        // M416
        {1101004046, {1101004046, 1010040474, 1010040475, 1010040476, 1010040471, 1010040472, 1010040473, 1010040485, 1010040470, 1010040469, 1010040468, 1010040467, 1010040466, 1010040481, 0, 1010040479, 1010040477, 1010040482, 1010040478, 1010040484, 1010040483, 1010040480, 0, 0}},
        {1101004062, {1101004062, 1010040578, 1010040577, 1010040579, 1010040575, 1010040570, 1010040576, 1010040590, 1010040569, 1010040568, 1010040567, 1010040566, 1010040565, 1010040564, 0, 1010040585, 1010040580, 1010040587, 1010040588, 1010040483, 1010040589, 1010040586, 0, 0}},
        {1101004226, {1101004226, 1010042238, 1010042237, 1010042239, 1010042235, 1010042234, 1010042236, 1010042248, 1010042233, 1010042232, 1010042231, 1010042219, 1010042218, 1010042217, 0, 1010042243, 1010042241, 1010042245, 1010042246, 1010042247, 1010042242, 1010042244, 0, 0}},
        {1101004236, {1101004236, 1010042307, 1010042306, 1010042308, 1010042304, 1010042300, 1010042305, 1010042319, 1010042299, 1010042298, 1010042297, 1010042296, 1010042295, 1010042294, 0, 1010042314, 1010042309, 1010042316, 1010042317, 1010042318, 1010042310, 1010042315, 0, 0}},
        {1101004201, {1101004201, 1010041956, 1010041957, 1010041958, 1010041949, 1010041950, 1010041955, 0, 1010041948, 1010041947, 1010041946, 1010041945, 1010041944, 1010041967, 0, 1010041965, 1010041959, 0, 0, 0, 1010041960, 1010041966, 0, 0}},
        {1101004209, {1101004209, 1010042038, 1010042037, 1010042039, 1010042034, 1010042035, 1010042036, 1010042055, 1010042029, 1010042028, 1010042027, 1010042026, 1010042025, 1010042024, 0, 1010042046, 1010042044, 1010042048, 1010042049, 1010042054, 1010042045, 1010042047, 0, 0}},
        {1101004218, {1101004218, 1010042128, 1010042127, 1010042129, 1010042124, 1010042125, 1010042126, 1010042145, 1010042119, 1010042118, 1010042117, 1010042116, 1010042115, 1010042114, 0, 1010042136, 1010042134, 1010042138, 1010042139, 1010042144, 1010042135, 1010042137, 0, 0}},
        // AKM
        {1101001213, {1101001213, 1010012067, 1010012068, 1010012069, 1010012072, 1010012070, 1010012073, 0, 1010012066, 1010012065, 1010012064, 1010012063, 1010012062, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {1101001231, {1101001231, 1010012267, 1010012268, 1010012269, 1010012273, 1010012272, 1010012274, 1010012275, 1010012266, 1010012265, 1010012264, 1010012263, 1010012262, 1010012276, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {1101001242, {1101001242, 1010012357, 1010012357, 1010012359, 1010012363, 1010012362, 1010012364, 1010012365, 1010012356, 1010012355, 1010012354, 1010012353, 1010012352, 1010012366, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {1101001256, {1101001256, 1010012507, 1010012508, 1010012509, 1010012513, 1010012512, 1010012514, 1010012515, 1010012506, 1010012505, 1010012504, 1010012503, 1010012502, 1010012516, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {1101001249, {1101001249, 1010012437, 1010012438, 1010012439, 1010012443, 1010012442, 1010012444, 1010012445, 1010012436, 1010012435, 1010012434, 1010012433, 1010012432, 1010012446, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        // SCAR-L
        {1101003167, {1101003167, 1010031609, 1010031610, 1010031613, 1010031608, 1010031607, 1010031617, 1010031623, 1010031606, 1010031605, 1010031604, 1010031603, 1010031602, 1010031618, 0, 1010031615, 1010031614, 1010031620, 1010031622, 1010031619, 1010031616, 0, 0, 0}},
        {1101003181, {1101003181, 1010031765, 1010031764, 1010031766, 1010031759, 1010031758, 1010031763, 1010031775, 1010031757, 1010031756, 1010031755, 1010031754, 1010031753, 1010031752, 0, 1010031769, 1010031767, 1010031773, 1010031774, 1010031772, 1010031768, 0, 0, 0}},
        {1101003195, {1101003195, 1010031912, 1010031911, 1010031913, 1010031908, 1010031907, 1010031909, 1010031921, 1010031906, 1010031905, 1010031904, 1010031903, 1010031902, 1010031901, 0, 1010031916, 1010031914, 1010031918, 1010031919, 1010031917, 1010031915, 0, 0, 0}},
        {1101003208, {1101003208, 1010032034, 1010032033, 1010032045, 1010032029, 1010032028, 1010032032, 0, 1010032027, 1010032026, 1010032025, 1010032024, 1010032023, 1010032022, 0, 1010032038, 1010032036, 1010032042, 1010032043, 1010032039, 1010032037, 0, 0, 0}},
        // AUG
        {1101006062, {1101006062, 1010060573, 1010060572, 1010060574, 1010060564, 1010060563, 1010060565, 1010060593, 1010060562, 1010060561, 1010060554, 1010060553, 1010060552, 1010060551, 0, 1010060583, 1010060581, 1010060591, 1010060592, 1010060584, 1010060582, 0, 0, 0}},
        {1101006075, {1101006075, 1010060702, 1010060701, 1010060703, 1010060698, 1010060697, 1010060699, 1010060711, 1010060696, 1010060695, 1010060694, 1010060693, 1010060692, 1010060691, 0, 1010060706, 1010060704, 1010060708, 1010060709, 1010060707, 1010060705, 0, 0, 0}},
        // M762
        {1101008126, {1101008126, 1010081210, 1010081213, 1010081215, 1010081208, 1010081207, 1010081209, 0, 1010081206, 1010081205, 1010081204, 1010081203, 1010081202, 1010081218, 0, 1010081217, 1010081216, 0, 0, 0, 1010081214, 0, 0, 0}},
        {1101008136, {1101008136, 1010081314, 1010081315, 1010081316, 1010081312, 1010081308, 1010081313, 1010081326, 1010081307, 1010081306, 1010081305, 1010081304, 1010081303, 1010081302, 0, 1010081318, 1010081317, 1010081322, 1010081323, 1010081325, 1010081324, 0, 0, 0}},
        {1101008146, {1101008146, 1010081401, 1010081402, 1010081403, 1010081398, 1010081397, 1010081399, 1010081411, 1010081396, 1010081395, 1010081394, 1010081393, 1010081392, 1010081391, 0, 1010081405, 1010081404, 1010081406, 1010081407, 1010081409, 1010081408, 0, 0, 0}},
        {1101008154, {1101008154, 1010081531, 1010081532, 1010081533, 1010081527, 1010081528, 1010081529, 1010081411, 1010081526, 1010081525, 1010081524, 1010081523, 1010081522, 1010081521, 0, 1010081541, 1010081534, 1010081542, 1010081543, 1010081545, 1010081544, 0, 0, 0}},
        // ACE32
        {1101102007, {1101102007, 1011020027, 1011020028, 1011020029, 1011020025, 1011020024, 1011020026, 1011020045, 1011020019, 1011020018, 1011020017, 1011020016, 1011020015, 1011020014, 0, 1011020036, 1011020034, 1011020038, 1011020039, 1011020044, 1011020035, 1011020037, 0, 0}},
        {1101102017, {1011020127, 1011020127, 1011020128, 1011020129, 1011020125, 1011020124, 1011020126, 1011020145, 1011020119, 1011020118, 1011020117, 1011020116, 1011020115, 1011020114, 0, 1011020136, 1011020134, 1011020138, 1011020139, 1011020144, 1011020135, 1011020137, 0, 0}},
        {1101102025, {1101102025, 1011020214, 1011020215, 1011020216, 1011020212, 1011020211, 1011020213, 1011020225, 1011020209, 1011020208, 1011020207, 1011020206, 1011020205, 1011020204, 0, 1011020219, 1011020217, 1011020222, 1011020223, 1011020224, 1011020218, 1011020221, 0, 0}},
        // QBZ
        {1101007046, {1101007046, 1010070410, 1010070413, 1010070414, 1010070408, 1010070407, 1010070409, 0, 1010070406, 1010070405, 1010070404, 1010070403, 1010070402, 1011020204, 0, 1010070416, 1010070415, 0, 0, 0, 1010070417, 0, 0, 0}},
        {1101007062, {1101007062, 1010070579, 1010070578, 1010070581, 1010070576, 1010070575, 1010070577, 1010070588, 1010070406, 1010070405, 1010070404, 1010070403, 1010070402, 1011020204, 0, 1010070584, 1010070582, 1010070585, 1010070586, 1010070587, 1010070583, 0, 0, 0}},
        {1101007071, {1101007071, 1010070663, 1010070662, 1010070664, 1010070659, 1010070658, 1010070660, 1010070588, 1010070657, 1010070656, 1010070655, 1010070654, 1010070653, 1010070652, 0, 1010070667, 1010070665, 1010070668, 1010070669, 1010070670, 1010070666, 0, 0, 0}},
        // UZI
        {1102001120, {1102001120, 1020011137, 1020011138, 1020011139, 1020011135, 1020011134, 1020011136, 0, 1020011133, 1020011132, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1020011142, 0, 0}},
        // UMP45
        {1102002136, {1102002136, 1020021314, 1020021313, 1020021315, 1020021309, 1020021308, 1020021312, 1020021325, 1020021307, 1020021306, 1020021305, 1020021304, 1020021303, 1020021302, 0, 1020021318, 1020021316, 1020021323, 1020021324, 1020021322, 1020021317, 0, 0, 0}},
        // Vector
        {1102003080, {1102003080, 1020030755, 1020030756, 1020030758, 1020030750, 1020030749, 1020030754, 0, 1020030748, 1020030747, 1020030746, 1020030745, 1020030744, 1020030764, 0, 1020030760, 0, 1020030759, 1020030757, 0, 0, 1020030765, 0, 0}},
        // Kar98K
        {1103001179, {1103001179, 1030011738, 1030011739, 1030011741, 0, 0, 0, 1030011743, 1030011737, 1030011736, 1030011735, 1030011734, 1030011733, 1030011732, 1030011731, 0, 0, 0, 0, 0, 0, 0, 1030011742, 1030011744}},
        {1103001191, {1103001191, 1030011858, 1030011859, 1030011851, 0, 0, 0, 1030011863, 1030011857, 1030011856, 1030011855, 1030011854, 1030011853, 1030011852, 1030011851, 0, 0, 0, 0, 0, 0, 0, 1030011862, 1030011864}},
        // M24
        {1103002087, {1103002087, 1030020824, 1030020825, 1030020826, 0, 0, 0, 1030020828, 1030020818, 1030020817, 1030020816, 1030020815, 1030020814, 1030020813, 1030020812, 0, 0, 0, 0, 0, 0, 0, 1030020827, 0}},
        // AWM
        {1103003087, {1103003087, 1030030825, 1030030826, 1030030827, 1030030823, 1030030822, 1030030824, 1030030819, 1030030818, 1030030817, 1030030816, 1030030815, 1030030814, 1030030813, 1030030812, 0, 0, 0, 0, 0, 0, 0, 1030030828, 0}},
        // AMR
        {1103012010, {1103012010, 0, 0, 0, 0, 0, 0, 0, 1030120038, 1030120037, 1030120036, 1030120035, 1030120034, 1030120033, 1030120032, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {1103012019, {1103012019, 0, 0, 0, 0, 0, 0, 0, 1030120138, 1030120137, 1030120136, 1030120135, 1030120134, 1030120133, 1030120132, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {1103012031, {1103012031, 0, 0, 0, 0, 0, 0, 0, 1030120258, 1030120257, 1030120256, 1030120255, 1030120254, 1030120253, 1030120252, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        // Mk14
        {1103007028, {1103007028, 1030070228, 1030070228, 1030070232, 1030070223, 1030070222, 1030070224, 1030070219, 1030070218, 1030070217, 1030070216, 1030070215, 1030070214, 1030070213, 1030070212, 0, 0, 0, 0, 0, 0, 0, 1030070236, 0}},
        // MG3
        {1105010019, {1105010019, 0, 0, 0, 0, 0, 0, 0, 1050100144, 1050100143, 1050100142, 1050100141, 1050100139, 1050100138, 0, 0, 0, 0, 0, 0, 0, 0, 1030070236, 0}}
    };
    return skinMap.count(id) ? skinMap.at(id) : Gun{id};
}

void ChangeGunSkin(ASTExtraWeapon* gun) {
    if (isObjectInvalid(gun) || gun->Owner != g_LocalPlayer) return;
    int newid = gun->GetWeaponID(), newgun = GetWeap(newid);
    if (newgun > 0) GetFullWeapon(newgun).ChangeSkin(gun);
}

template<typename T>
void GetAllActorsT(std::vector<T*>& Trace) {
    UGameplayStatics* gGameplayStatics = (UGameplayStatics*)gGameplayStatics->StaticClass();
    auto GWorld = GetWorld();
    if (!GWorld || !GWorld->PersistentLevel) return;

    TArray<AActor*> Actors;
    gGameplayStatics->GetAllActorsOfClass((UObject*)GWorld, T::StaticClass(), &Actors);
    Trace.clear();
    for (int i = 0; i < Actors.Num(); i++) {
        if (Actors[i] && Actors[i]->IsA(T::StaticClass())) Trace.push_back((T*)Actors[i]);
    }
}

bool carspring = false;
std::string item_separated_by_zero(std::vector<FSkinItem> skins) {
    std::string out;
    if (skins.empty()) return out;
    for (size_t i = 0; i < skins.size(); i++) {
        out += skins[i].name;
        out += '\0';
    }
    return out;
}

void RenderSkinItem(std::string label, CSkinsInfo& skins, on_change_callback cb) {
    ImGui::TableNextRow();

    ImGui::TableSetColumnIndex(0);
    std::string combo_label = "##" + label + "##combo";
    ImGui::PushItemWidth(120);
    if (!skins.items.empty()) {
        const char* items_str = item_separated_by_zero(skins.items).c_str();
        if (ImGui::Combo(combo_label.c_str(), &skins.current_index, items_str)) {
            if (skins.out) *skins.out = skins.Get();
        }
    } else {
        ImGui::Text("No items");
    }
    ImGui::PopItemWidth();

    ImGui::TableSetColumnIndex(1);
    ImGui::Text(label.c_str());

    ImGui::TableSetColumnIndex(2);
    std::string input_label = "##" + label + "##input";
    if (skins.out) {
        ImGui::PushItemWidth(80);
        ImGui::InputScalar(input_label.c_str(), ImGuiDataType_U32, skins.out);
        ImGui::PopItemWidth();
    }
}

bool UpdateClothSkin(UCharacterAvatarComponent2 *avatar) {
    if (!g_LocalPlayer) return false;
    if (!g_LocalPlayer->AvatarComponent2) return false;
    if (avatar != g_LocalPlayer->AvatarComponent2) return false;
    FNetAvatarSyncData NetAvatarComp = *(FNetAvatarSyncData *)((uintptr_t)avatar + 0x550);
    auto slot = NetAvatarComp.SlotSyncData;
    for (int i = 0; i < slot.Num(); i++) {
        auto& id = slot[i].ItemId;
        auto sl = slot[i].SlotID;
        if (sl == 3 && skin.cloth->HAT > 0)   id = skin.cloth->HAT;
        if (sl == 5 && skin.cloth->SHIRT > 0)  id = skin.cloth->SHIRT;
        if (sl == 6 && skin.cloth->PANT > 0)   id = skin.cloth->PANT;
        if (sl == 7 && skin.cloth->SHOE > 0)   id = skin.cloth->SHOE;
        switch (id) { case 502004: case 502001: case 502110: case 502107: case 502104:
            if (sl == 9 && id > 0 && skin.cloth->HELMET1 > 0) id = skin.cloth->HELMET1; break; }
        switch (id) { case 502005: case 502002: case 502111: case 502108: case 502105:
            if (sl == 9 && id > 0 && skin.cloth->HELMET2 > 0) id = skin.cloth->HELMET2; break; }
        switch (id) { case 502106: case 502109: case 502112: case 502003:
            if (sl == 9 && id > 0 && skin.cloth->HELMET3 > 0) id = skin.cloth->HELMET3; break; }
        switch (id) { case 501001: case 501004: case 501007: case 501010: case 501101: case 501104:
            if (sl == 8 && id > 0 && skin.cloth->BACKPACK1 > 0) id = skin.cloth->BACKPACK1; break; }
        switch (id) { case 501002: case 501005: case 501008: case 501011: case 501102: case 501105:
            if (sl == 8 && id > 0 && skin.cloth->BACKPACK2 > 0) id = skin.cloth->BACKPACK2; break; }
        switch (id) { case 501006: case 501003: case 501009: case 501012: case 501015: case 501106: case 501103:
            if (sl == 8 && id > 0 && skin.cloth->BACKPACK3 > 0) id = skin.cloth->BACKPACK3; break; }
        if (sl == 11 && id > 0 && skin.cloth->PARACHUTE > 0) id = skin.cloth->PARACHUTE;
        if (sl == 15 && skin.cloth->GLIDER > 0)               id = skin.cloth->GLIDER;
    }
    return true;
}

bool UpdateClothSkinLobby(UCharacterAvatarComponent2 *avatar) {
    FNetAvatarSyncData NetAvatarComp = *(FNetAvatarSyncData *)((uintptr_t)avatar + 0x550);
    auto slot = NetAvatarComp.SlotSyncData;
    for (int i = 0; i < slot.Num(); i++) {
        auto& id = slot[i].ItemId;
        auto sl = slot[i].SlotID;
        if (sl == 3 && skin.cloth->HAT > 0)   id = skin.cloth->HAT;
        if (sl == 5 && skin.cloth->SHIRT > 0)  id = skin.cloth->SHIRT;
        if (sl == 6 && skin.cloth->PANT > 0)   id = skin.cloth->PANT;
        if (sl == 7 && skin.cloth->SHOE > 0)   id = skin.cloth->SHOE;
        switch (id) { case 502004: case 502001: case 502110: case 502107: case 502104:
            if (sl == 9 && id > 0 && skin.cloth->HELMET1 > 0) id = skin.cloth->HELMET1; break; }
        switch (id) { case 502005: case 502002: case 502111: case 502108: case 502105:
            if (sl == 9 && id > 0 && skin.cloth->HELMET2 > 0) id = skin.cloth->HELMET2; break; }
        switch (id) { case 502106: case 502109: case 502112: case 502003:
            if (sl == 9 && id > 0 && skin.cloth->HELMET3 > 0) id = skin.cloth->HELMET3; break; }
        switch (id) { case 501001: case 501004: case 501007: case 501010: case 501101: case 501104:
            if (sl == 8 && id > 0 && skin.cloth->BACKPACK1 > 0) id = skin.cloth->BACKPACK1; break; }
        switch (id) { case 501002: case 501005: case 501008: case 501011: case 501102: case 501105:
            if (sl == 8 && id > 0 && skin.cloth->BACKPACK2 > 0) id = skin.cloth->BACKPACK2; break; }
        switch (id) { case 501006: case 501003: case 501009: case 501012: case 501015: case 501106: case 501103:
            if (sl == 8 && id > 0 && skin.cloth->BACKPACK3 > 0) id = skin.cloth->BACKPACK3; break; }
        if (sl == 11 && id > 0 && skin.cloth->PARACHUTE > 0) id = skin.cloth->PARACHUTE;
        if (sl == 15 && skin.cloth->GLIDER > 0)               id = skin.cloth->GLIDER;
    }
    return true;
}

void(*orig_kill_message_event)(ASTExtraPlayerController*, FFatalDamageParameter*);
void kill_message_event(ASTExtraPlayerController* PlayerController, FFatalDamageParameter* FatalDamageParameter) {
    if (skin.bEnable && skin.bKillMsg && PlayerController->PlayerKey == FatalDamageParameter->CauserKey) {
        FatalDamageParameter->CauserClothAvatarID = skin.cloth->SHIRT;
        if (Last_Gun_Used_To_Kill > 0) FatalDamageParameter->CauserWeaponAvatarID = Last_Gun_Used_To_Kill;
    }
    if (Config.Memory.FakeName) {
        FatalDamageParameter->String.causerName      = FString("(NBC)RAC");
        FatalDamageParameter->String.FuzzyCauserName = FString("(NBC)RAC");
        FatalDamageParameter->String.RealKillerName  = FString("(NBC)RAC");
    }
    orig_kill_message_event(PlayerController, FatalDamageParameter);
}

DWORD GetVehSkinModded(DWORD old) {
    static const std::unordered_map<DWORD, DWORD> vehSkinMap = {
        {1901001, skin.vehicle->MOTOR}, {1901002, skin.vehicle->MOTOR}, {1961001, skin.vehicle->COUPE},
        {1908001, skin.vehicle->UAZ},   {1910001, skin.vehicle->UAZ},   {1903001, skin.vehicle->DACIA},
        {1914001, skin.vehicle->MIRADO},{1914002, skin.vehicle->MIRADO},{1914003, skin.vehicle->MIRADO},
        {1914004, skin.vehicle->MIRADO},{1915001, skin.vehicle->MIRADO},{1915002, skin.vehicle->MIRADO},
        {1915003, skin.vehicle->MIRADO},{1915004, skin.vehicle->MIRADO},{1907001, skin.vehicle->BUGGY},
        {1907002, skin.vehicle->BUGGY}, {1907003, skin.vehicle->BUGGY}, {1907004, skin.vehicle->BUGGY},
        {1907005, skin.vehicle->BUGGY}, {1907006, skin.vehicle->BUGGY}
    };
    return vehSkinMap.count(old) ? vehSkinMap.at(old) : 0;
}


// ── Vector helper stubs ──────────────────────────────────────────────────────
static inline FVector AddVectors(const FVector& a, const FVector& b) {
    return { a.X + b.X, a.Y + b.Y, a.Z + b.Z };
}
static inline FVector SubtractVectors(const FVector& a, const FVector& b) {
    return { a.X - b.X, a.Y - b.Y, a.Z - b.Z };
}
static inline FVector MultiplyVectorFloat(const FVector& v, float f) {
    return { v.X * f, v.Y * f, v.Z * f };
}
static inline FRotator VectorToRotator(const FVector& dir) {
    float yaw   = atan2f(dir.Y, dir.X) * (180.f / 3.14159265f);
    float pitch = atan2f(dir.Z, sqrtf(dir.X*dir.X + dir.Y*dir.Y)) * (180.f / 3.14159265f);
    return { pitch, yaw, 0.f };
}

ASTExtraPlayerCharacter* GetBestLineTarget() {
    AimResult ar = GetTargetByCrossDist();
    return ar.player;
}

void* (*oProcessEvent)(UObject*, UFunction*, void*);
void* hkProcessEvent(UObject* a1, UFunction* a, void* b) {
    if (!a1 || !a) return oProcessEvent(a1, a, b);

    auto fnc   = a->GetFullName();
    auto clazz = a1->GetFullName();

    if (ReceiveDrawHUD_Index == -1              && fnc.find("Function Engine.HUD.ReceiveDrawHUD") != std::string::npos)                                                          ReceiveDrawHUD_Index = a->InternalIndex;
    if (OnRep_AvatarMeshChanged_Index == -1     && fnc.find("ShadowTrackerExtra.STExtraWeapon.OnRep_AvatarMeshChanged") != std::string::npos)                                   OnRep_AvatarMeshChanged_Index = a->InternalIndex;
    if (CreateBattleItemHandle_Index == -1      && fnc.find("BackpackBlueprintUtils_BP_C.CreateBattleItemHandle") != std::string::npos)                                         CreateBattleItemHandle_Index = a->InternalIndex;
    if (CreateWeaponAndChangeSkin_Index == -1   && fnc.find("CreateWeaponAndSkin") != std::string::npos)                                                                        CreateWeaponAndChangeSkin_Index = a->InternalIndex;
    if (OnRep_BodySlotStateChanged_Index == -1  && fnc.find("ShadowTrackerExtra.CharacterAvatarComponent2.OnRep_BodySlotStateChanged") != std::string::npos)                   OnRep_BodySlotStateChanged_Index = a->InternalIndex;
    if (skin.bDeadbox && DeadBoxAvatarComponent_GetLuaFilePath_Index == -1 && clazz.find("DeadBoxAvatarComponent_BP") != std::string::npos && fnc.find("GetLuaFilePath") != std::string::npos) DeadBoxAvatarComponent_GetLuaFilePath_Index = a->InternalIndex;

    if (g_LocalPlayer && g_LocalController && Config.ESPMenu.Instant && fnc.find("ClientOnDamageToOther") != std::string::npos) {
        auto localContrller = reinterpret_cast<ASTExtraPlayerController*>(a1);
        auto Params = reinterpret_cast<ASTExtraPlayerController_ClientOnDamageToOther_Params*>(b);
        if (Params) {
            auto damage = Params->_DamageToOther;
            if (auto HUD = reinterpret_cast<ASurviveHUD*>(localContrller->MyHUD))
                HUD->AddHitDamageNumberWithConfig(damage, g_LocalPlayer, g_LocalController, 0, 1, 1, 1);
        }
    }

    if (fnc.find("UpdateVolleyShootParameters") != std::string::npos) {
        auto params = (USTExtraShootWeaponComponent_UpdateVolleyShootParameters_Params*)b;

        // SilentAim через ProcessEvent
        if (Config.SilentAim.Enable && g_LocalPlayer && g_LocalController && params) {
            ASTExtraPlayerCharacter* saTarget = nullptr;
            float saBest = std::numeric_limits<float>::infinity();
            auto saActors = GetActors();
            float saMaxDist = Config.SilentAim.MaxDistance * 100.0f;

            for (auto saActor : saActors) {
                if (isObjectInvalid(saActor)) continue;
                if (!saActor->IsA(ASTExtraPlayerCharacter::StaticClass())) continue;
                auto* saPlayer = (ASTExtraPlayerCharacter*)saActor;
                if (saPlayer->PlayerKey == g_LocalPlayer->PlayerKey) continue;
                if (saPlayer->TeamID == g_LocalPlayer->TeamID) continue;
                if (saPlayer->bDead) continue;
                if (Config.SilentAim.IgnoreKnocked && saPlayer->Health == 0.0f) continue;
                if (Config.SilentAim.IgnoreBot && saPlayer->bEnsure) continue;
                float saDist = g_LocalPlayer->GetDistanceTo(saPlayer);
                if (saDist > saMaxDist) continue;
                if (Config.SilentAim.VisibleCheck && !g_LocalController->LineOfSightTo(saPlayer, {0,0,0}, true)) continue;

                const char* saBone = "Head";
                switch ((int)Config.SilentAim.TargetBone) {
                    case 1: saBone = "neck_01"; break;
                    case 2: saBone = "spine_03"; break;
                    case 3: saBone = "pelvis"; break;
                    case 4: { const char* bl[] = {"Head","neck_01","spine_03","pelvis","hand_r","hand_l"}; saBone = bl[rand()%6]; break; }
                    default: saBone = "Head"; break;
                }

                FVector saBonePos = saPlayer->GetBonePos(saBone, {});
                FVector2D saScreen;
                float saVal = saDist;
                if (Config.SilentAim.FOV > 0.0f) {
                    if (W2S_DIRECT(saBonePos, &saScreen)) {
                        float dx = saScreen.X - glWidth/2.f;
                        float dy = saScreen.Y - glHeight/2.f;
                        float rad = Config.SilentAim.FOV * 0.5f;
                        if (dx*dx + dy*dy > rad*rad) continue;
                        saVal = sqrtf(dx*dx + dy*dy);
                    } else continue;
                }
                if (saVal < saBest) { saBest = saVal; saTarget = saPlayer; }
            }

            if (saTarget) {
                bool saTrigger = false;
                switch (Config.SilentAim.Trigger) {
                    case 0: saTrigger = true; break;
                    case 1: saTrigger = g_LocalPlayer->bIsWeaponFiring; break;
                    case 2: saTrigger = g_LocalPlayer->bIsGunADS; break;
                    case 3: saTrigger = g_LocalPlayer->bIsWeaponFiring || g_LocalPlayer->bIsGunADS; break;
                    default: saTrigger = false; break;
                }
                if (saTrigger) {
                    const char* saBone2 = "Head";
                    switch ((int)Config.SilentAim.TargetBone) {
                        case 1: saBone2 = "neck_01"; break;
                        case 2: saBone2 = "spine_03"; break;
                        case 3: saBone2 = "pelvis"; break;
                        case 4: { const char* bl[] = {"Head","neck_01","spine_03","pelvis","hand_r","hand_l"}; saBone2 = bl[rand()%6]; break; }
                        default: saBone2 = "Head"; break;
                    }
                    FVector saAimPos = saTarget->GetBonePos(saBone2, {});
                    if (std::isfinite(saAimPos.X) && std::isfinite(saAimPos.Y) && std::isfinite(saAimPos.Z)) {
                        FVector saVel = saTarget->GetVelocity();
                        FVector saLocal = g_LocalController->PlayerCameraManager->CameraCache.POV.Location;
                        FVector saRel = VectorSubtract(saAimPos, saLocal);
                        float saSpeed = 750.f;
                        float saA = VectorSizeSquared(saVel) - saSpeed*saSpeed;
                        float saB = 2.f * VectorDot(saRel, saVel);
                        float saC = VectorSizeSquared(saRel);
                        float saDisc = saB*saB - 4.f*saA*saC;
                        if (std::isfinite(saA) && std::isfinite(saB) && std::isfinite(saC) && saDisc >= 0.f) {
                            float saSqrt = sqrtf(saDisc);
                            float st1 = (-saB - saSqrt) / (2.f*saA);
                            float st2 = (-saB + saSqrt) / (2.f*saA);
                            float st = (st1 > 0.f) ? st1 : ((st2 > 0.f) ? st2 : -1.f);
                            if (st > 0.f && st < 1.5f)
                                saAimPos = VectorAdd(saAimPos, VectorMultiply(saVel, st));
                        } else {
                            float saDist2 = VectorSize(saRel);
                            if (std::isfinite(saDist2) && saDist2 > 0.f)
                                saAimPos = VectorAdd(saAimPos, VectorMultiply(saVel, saDist2/saSpeed));
                        }
                        FVector saDir = SubtractVectors(saLocal, saAimPos);
                        params->BulletRot = VectorToRotator(saDir);
                    }
                }
            }
        }

        if (Config.Ragebot.Aimtype == 1 && Config.Ragebot.Enable) {
            auto Target = GetBestLineTarget();
            if (Target) {
                bool triggerOk = false;
                switch (Config.Ragebot.Trigger) {
                    case (int)EAimTrigger::Shooting: triggerOk = g_LocalPlayer->bIsWeaponFiring; break;
                    case (int)EAimTrigger::Scoping:  triggerOk = g_LocalPlayer->bIsFPPOnVehicle; break;
                    case (int)EAimTrigger::Both:     triggerOk = g_LocalPlayer->bIsWeaponFiring && g_LocalPlayer->bIsGunADS; break;
                    case (int)EAimTrigger::Any:      triggerOk = g_LocalPlayer->bIsWeaponFiring || g_LocalPlayer->bIsGunADS; break;
                    default: triggerOk = true;
                }
                if (triggerOk) {
                    FVector TargetAimPosition = Target->GetBonePos("Head", {});
                    TargetAimPosition.Z -= -19.0f;
                    auto CurrentWeaponReplicated = (ASTExtraShootWeapon*)g_LocalPlayer->WeaponManagerComponent->CurrentWeaponReplicated;
                    auto CurrentVehicle = Target->CurrentVehicle;
                    CurrentWeaponReplicated->ShootMode = EShootWeaponShootMode::SWST_TraceTarget;
                    float BulletFireSpeed = CurrentWeaponReplicated->GetBulletFireSpeedFromEntity();
                    FVector CurrentPlayerVelocity = CurrentVehicle ? CurrentVehicle->ReplicatedMovement.LinearVelocity : Target->GetVelocity();
                    float Distance = g_LocalPlayer->GetDistanceTo(Target);
                    auto TimeToTravel = Distance / BulletFireSpeed;
                    TargetAimPosition = AddVectors(TargetAimPosition, MultiplyVectorFloat(CurrentPlayerVelocity, TimeToTravel));
                    FVector fDir = SubtractVectors(g_LocalController->PlayerCameraManager->CameraCache.POV.Location, TargetAimPosition);
                    params->BulletRot = VectorToRotator(fDir);
                }
            }
        }
    }

    if (skin.bEnable) {
        if (skin.bGunSkin && OnRep_AvatarMeshChanged_Index == a->InternalIndex) {
            auto gun = reinterpret_cast<ASTExtraWeapon*>(a1);
            if (gun) ChangeGunSkin(gun);
        } else if (!g_LocalController && skin.bVehicleSkin && fnc.find("VehicleAvatarComponent_BP.VehicleAvatarComponent_BP_C.GetItemAvatarHandle") != std::string::npos) {
            auto PARAMS = reinterpret_cast<UVehicleAvatarComponent_GetItemAvatarHandle_Params*>(b);
            if (PARAMS) {
                int neww = GetVehSkinModded(PARAMS->ItemId);
                if (neww > 0) PARAMS->ItemId = neww;
            }
        } else if (!g_LocalController && skin.bClothSkin && fnc.find(skCrypt("OnAvatarMeshEquippedEventBP")) != std::string::npos) {
            auto avatar = reinterpret_cast<UCharacterAvatarComponent2*>(a1);
            if (avatar) UpdateClothSkinLobby(avatar);
        } else if (g_LocalController && skin.bClothSkin && OnRep_BodySlotStateChanged_Index == a->InternalIndex) {
            auto avatar = reinterpret_cast<UCharacterAvatarComponent2*>(a1);
            if (avatar) UpdateClothSkin(avatar);
        } else if (skin.bGunSkin && CreateWeaponAndChangeSkin_Index == a->InternalIndex) {
            auto params = reinterpret_cast<ULobbyWeaponManagerComponent_CreateWeaponAndSkin_Params*>(b);
            if (params) {
                params->bSync   = false;
                params->bUse    = true;
                int g_WeaponID  = params->WeaponSkinID;
                DWORD gun_val   = GetWeap(g_WeaponID);
                if (gun_val > 0) params->WeaponSkinID = gun_val;
            }
        } else if (skin.bDeadbox && DeadBoxAvatarComponent_GetLuaFilePath_Index == a->InternalIndex && a1->GetName().find("DeadBoxAvatarComponent") != std::string::npos) {
            auto DeadBoxPointer = reinterpret_cast<UDeadBoxAvatarComponent*>(a1);
            if (DeadBoxPointer && Last_Gun_Used_To_Kill > 0) DeadBoxPointer->AsyncChangeItemAvatar(Last_Gun_Used_To_Kill);
        }
    }

    return oProcessEvent(a1, a, b);
}


void DrawMemory(UCanvas* /*Canvas*/, float /*SizeX*/, float /*SizeY*/) {}

void* (*oPostRender)(UGameViewportClient*, UCanvas*);
void* PostRender(UGameViewportClient* GameViewport, UCanvas* Canvas) {
    DrawMemory(Canvas, Canvas->SizeX, Canvas->SizeY);
    return oPostRender(GameViewport, Canvas);
}

void PostrenderDraw() {
    auto GViewport = GetGameViewport();
    if (GViewport) {
        int postrender_idx = 134;
        auto f_mprotect = [](uintptr_t addr, size_t len, int32_t prot) -> int32_t {
            static_assert(PAGE_SIZE == 4096);
            constexpr size_t page_size = static_cast<size_t>(PAGE_SIZE);
            void* start = reinterpret_cast<void*>(addr & -page_size);
            uintptr_t end = (addr + len + page_size - 1) & -page_size;
            return mprotect(start, end - reinterpret_cast<uintptr_t>(start), prot);
        };
        auto VTable = (void**)GViewport->VTable;
        if (VTable && (VTable[postrender_idx] != PostRender)) {
            oPostRender = decltype(oPostRender)(VTable[postrender_idx]);
            f_mprotect((uintptr_t)(&VTable[postrender_idx]), sizeof(uintptr_t), PROT_READ | PROT_WRITE);
            VTable[postrender_idx] = (void*)PostRender;
        }
    }
}

// ── end SkinMain.h ────────────────────────────────────────────────────────────

// Hooks for libanogs.so


// sub_51fa80 at 0x51fa80
__int64 (*osub_51fa80)(__int64 a1, __int64 a2, __int64 a3, __int64 a4) = 0;

__int64 __fastcall hsub_51fa80(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
    return 0;
}




// sub_1A9DEC at 0x1A9DEC
__int64 (*osub_1A9DEC)(__int64 a1, __int64 a2, __int64 a3, __int64 a4) = 0;

__int64 __fastcall hsub_1A9DEC(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
    return 0;
}



// sub_213058 at 0x213058
__int64 (*osub_213058)(__int64 a1, __int64 a2, __int64 a3, __int64 a4) = 0;

__int64 __fastcall hsub_213058(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
    return 0;
}



// sub_228164 at 0x228164
__int64 (*osub_228164)(__int64 a1, __int64 a2, __int64 a3, __int64 a4) = 0;

__int64 __fastcall hsub_228164(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
    return 0;
}




// sub_228360 at 0x228360
__int64 (*osub_228360)(__int64 a1, __int64 a2, __int64 a3, __int64 a4) = 0;

__int64 __fastcall hsub_228360(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
    return 0;
}




// sub_330494 at 0x330494
__int64 (*osub_330494)(__int64 a1, __int64 a2, __int64 a3, __int64 a4) = 0;

__int64 __fastcall hsub_330494(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
    return 0;
}



// sub_37C904 at 0x37C904
__int64 (*osub_37C904)(__int64 a1, __int64 a2, __int64 a3, __int64 a4) = 0;

__int64 __fastcall hsub_37C904(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
    return 0;
}




// sub_39F56C at 0x39F56C
__int64 (*osub_39F56C)(__int64 a1, __int64 a2, __int64 a3, __int64 a4) = 0;

__int64 __fastcall hsub_39F56C(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
    return 0;
}



// sub_3DFA14 at 0x3DFA14
__int64 (*osub_3DFA14)(__int64 a1, __int64 a2, __int64 a3, __int64 a4) = 0;

__int64 __fastcall hsub_3DFA14(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
    return 0;
}




// sub_3E4650 at 0x3E4650
__int64 (*osub_3E4650)(__int64 a1, __int64 a2, __int64 a3, __int64 a4) = 0;

__int64 __fastcall hsub_3E4650(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
    return 0;
}



// sub_3F9928 at 0x3F9928
__int64 (*osub_3F9928)(__int64 a1, __int64 a2, __int64 a3, __int64 a4) = 0;

__int64 __fastcall hsub_3F9928(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
    return 0;
}




// sub_49AA00 at 0x49AA00
__int64 (*osub_49AA00)(__int64 a1, __int64 a2, __int64 a3, __int64 a4) = 0;

__int64 __fastcall hsub_49AA00(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
    return 0;
}



// sub_49AA3C at 0x49AA3C
__int64 (*osub_49AA3C)(__int64 a1, __int64 a2, __int64 a3, __int64 a4) = 0;

__int64 __fastcall hsub_49AA3C(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
    return 0;
}




// sub_4B5E48 at 0x4B5E48
__int64 (*osub_4B5E48)(__int64 a1, __int64 a2, __int64 a3, __int64 a4) = 0;

__int64 __fastcall hsub_4B5E48(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
    return 0;
}

__int64 (*osub_32165C)(__int64 a1, __int64 a2, __int64 a3, __int64 a4) = 0;

__int64 __fastcall hsub_32165C(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
    return 0;
}

// @BYPASS_PAID 

// Hooks for libanogs.so


// sub_2234B0 at 0x2234B0
__int64 (*osub_2234B0)(__int64 a1, __int64 a2, __int64 a3, __int64 a4) = 0;

__int64 __fastcall hsub_2234B0(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
    return 0;
}



// sub_260B18 at 0x260B18
__int64 (*osub_260B18)(__int64 a1, __int64 a2, __int64 a3, __int64 a4) = 0;

__int64 __fastcall hsub_260B18(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
    return 0;
}




// sub_49A628 at 0x49A628
__int64 (*osub_49A628)(__int64 a1, __int64 a2, __int64 a3, __int64 a4) = 0;

__int64 __fastcall hsub_49A628(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
    return 0;
}




// sub_471B68 at 0x471B68
__int64 (*osub_471B68)(__int64 a1, __int64 a2, __int64 a3, __int64 a4) = 0;

__int64 __fastcall hsub_471B68(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
    return 0;
}

__int64 (*sub_451564)(__int64 a1, __int64 a2, __int64 a3, __int64 a4) = 0;

__int64 __fastcall osub_451564(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
    return 0;
}



void *ApplyHooks(void *)
{









// Patches for libanogs.so [RET] (C0 03 5F D6)

PATCH_LIB("libanogs.so", "0x3a4cd0", "C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x47b5cc", "C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x47b5d0", "C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x4dfbc0", "C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x5026f0", "C0 03 5F D6");
// Patches for libanogs.so [RET] (C0 03 5F D6)

PATCH_LIB("libanogs.so", "0x213000", "C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x229134", "C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x232980", "C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x3a4ccc", "C0 03 5F D6");
// Patches for libanogs.so [MOV X0] (00 00 80 D2 C0 03 5F D6)

PATCH_LIB("libanogs.so", "0x37fd78", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x39f56c", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x3b4480", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x3fc5c8", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x43694c", "00 00 80 D2 C0 03 5F D6");

HOOK_LIB("libanogs.so", "0x2234B0", hsub_2234B0, osub_2234B0);
HOOK_LIB("libanogs.so", "0x260B18", hsub_260B18, osub_260B18);
HOOK_LIB("libanogs.so", "0x49A628", hsub_49A628, osub_49A628);  
HOOK_LIB("libanogs.so", "0x471B68", hsub_471B68, osub_471B68);

PATCH_LIB("libanogs.so", "0x425864", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x446AD8", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x46270C", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x4690CC", "C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x47417C", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x49FC40", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x4B7D00", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x5026EC", "C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x50B808", "00 00 80 D2 C0 03 5F D6");

// Patches for libanogs.so [MOV X0] (00 00 80 D2 C0 03 5F D6)

PATCH_LIB("libanogs.so", "0x48F004", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x493EA8", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x1D37A8", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x1DBB0C", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x1C79D4", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x1CC128", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x1CCA7C", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x22B3D8", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x1CCA7C", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x1C8094", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x3762C4", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x44C600", "00 00 80 D2 C0 03 5F D6");
HOOK_LIB("libanogs.so", "0x451564", hsub_451564, osub_451564);
PATCH_LIB("libUE4.so","0x5ACC184","00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libUE4.so","0x62E286C","00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libUE4.so","0x68CD9C8","1F 20 03 D5");
PATCH_LIB("libanogs.so", "0x1CF5E4", "00 00 80 D2 C0 03 5F D6"); // 30 Day Fix, C35 Fix
PATCH_LIB("libanogs.so", "0x296654", "00 00 80 D2 C0 03 5F D6"); // C16 Fix
PATCH_LIB("libanogs.so", "0x2F7FF4", "00 00 80 D2 C0 03 5F D6"); // memset Fix
PATCH_LIB("libanogs.so", "0x3F2110", "C0 03 5F D6"); // Term Fix
PATCH_LIB("libanogs.so", "0x404D50", "C0 03 5F D6"); // 1 Day Fix, 10 Year Offline
PATCH_LIB("libanogs.so", "0x507938", "C0 03 5F D6"); // memcpy Fix, Strlen Fix
return nullptr;
}

void *main_thread(void *) {



UE4 = Tools::GetBaseAddress("libUE4.so");
while (!UE4) {
UE4 = Tools::GetBaseAddress("libUE4.so");
sleep(1);
}
g_Anogs = Tools::GetBaseAddress("libanogs.so");
while (!g_Anogs) {
g_Anogs = Tools::GetBaseAddress("libanogs.so");
sleep(1);
}



while (!g_App) {
g_App = *(android_app **) (UE4 + GNativeAndroidApp_Offset);
sleep(1);
}
FName::GNames = GetGNames();
while (!FName::GNames) {
FName::GNames = GetGNames();
sleep(1);
}

UObject::GUObjectArray = (FUObjectArray *) (UE4 + GUObject_Offset);
shadowhook_init(shadowhook_mode_t::SHADOWHOOK_MODE_UNIQUE, 0);
shadowhook_hook_sym_name("/system/lib64/libandroid.so", "ANativeWindow_getWidth",(void *)_ANativeWindow_getWidth,(void **)&orig_ANativeWindow_getWidth);
shadowhook_hook_sym_name("/system/lib64/libandroid.so", "ANativeWindow_getHeight",(void *)_ANativeWindow_getHeight,(void **)&orig_ANativeWindow_getHeight);
if (GetAndroidSdkVersion() < 35) {
shadowhook_hook_sym_name("/system/lib64/libinput.so", "_ZN7android13InputConsumer21initializeMotionEventEPNS_11MotionEventEPKNS_12InputMessageE",(void *)onInputEvent,(void **)&orig_onInputEvent); //Android 15 & above
}

if (GetAndroidSdkVersion() > 34) {
shadowhook_hook_sym_name("/system/lib64/libinput.so", "_ZN7android12_GLOBAL__N_121initializeMotionEventERNS_11MotionEventERKNS_12InputMessageE",(void *)onInputEvent,(void **)&orig_onInputEvent); //Android 15
}

// SilentAim перенесён в ProcessEvent (UpdateVolleyShootParameters) — Dobby хук отключён
// uintptr_t UpdateVolleyAddr = UE4 + UpdateVolley_Offset;
// DobbyHook((void*)UpdateVolleyAddr, (void*)UpdateVolley, (void**)&orig_UpdateVolley);


pthread_t t;
pthread_create(&t,NULL,main_thread,NULL);
items_data = json::parse(JSON_ITEMS);
return 0;
}
__attribute__((constructor)) void _init() {
WirexCrash::Init();
pthread_t t;
pthread_create(&t, 0, main_thread, 0);
pthread_create(&t, 0, RunOverlayThread, 0);
pthread_create(&t, 0, ApplyHooks, 0);
}
