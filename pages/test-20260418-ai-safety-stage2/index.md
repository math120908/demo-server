---
title: "Stage 2.2 · From Classification to Decision · Anthropic Cultural Fit"
theme: meridian-lite
lang: zh-TW
---

# 分類完 AI safety 之後, 下一步是什麼?

> 2026-04-18 · ROTOM · STAGE 2.2 / 7

從 Stage 2.1 的 3-lens 分類出發, 透過 5 個關鍵問題, 把風險描述推導到 Anthropic RSP 的骨架 — 不死背, 從第一原理推。完成這一站後, 你要能: (a) 解釋為什麼 gate 在 capability 而不是 alignment; (b) 從 harm vector 倒推出 capability categories; (c) 區分 RSP 的「承諾 disposition」vs「承諾 metric」。

:::card{label="📝 QUIZ" color="purple"}
**讀完這頁後**, 跑一次 Stage 2.2 Quiz (ASL / RSP 詞彙 + 場景判斷 · 含 Stage 2.3-2.4 preview)。新場景不照抄本頁, 強迫你在沒見過的情境下套用 capability-based gating 的判斷。
:::

---

:::card{label="🧩 Stage 2.1 交接 / HANDOFF" color="teal"}
## Stage 2.1 交接 — 在這裡要被升級

上一站結束時, 你手上有的是 **3 個 lens** (Misuse / Misalignment / Societal Disruption) — 這是風險的**分類框架**。但分類完, 一家 frontier lab 不能只靠分類做決定。這一站要做的事:

- **問題在哪裡**: Dario 手上放一份 Claude capability report — 三個 lens 能幫他「描述」報告裡的 risk, 但**不能告訴他要不要 ship**。分類 ≠ 決策程序。
- **本 stage 要做的**: 透過一系列問題, 看 CK 自己從第一原理推出 RSP 的骨架, 再對照 Anthropic 實際 instantiation, 找出對得上、漏掉的、以及 CK 原創比 Anthropic 更 sharp 的地方。
- **推導終點**: 一個 capability-gated deployment framework (ASL / RSP 的骨架), 和 3 個可以在面試現場直接用的 pivot。

:::callout
🎯 **這一站的 meta-move:** 我們**先不給你看 Anthropic 答案**, 每題都讓你先自己推, 再對照 Anthropic 實際做法。目標是: 面試現場被問到任何 RSP / ASL 問題, 你都能**從第一原理重新推出來**, 不需要 recall, 也不會 stuck 在 trivia 層級。
:::

:::

---

## 🧠 CK's Thinking Process · Q1-Q5

五個問題順序推進, 每題都是:「問題 → CK 的直覺回答 (verbatim) → 小節討論」。這一區的格式刻意與 Stage 2.1 的 three-lenses 區塊一致, 但主角是 CK 的推理軌跡, 不是 Anthropic 的 framework。

### Q1 — 當我們分類完 AI safety 的 topic 之後, 下個階段是什麼?

**CK 的直覺:**

> 因為我們要著重於 misalignment 的部分, 所以我在思考下一步應該是 ——
>
> 1. 我們要怎麼設定指標, 到底現在的 model 人類是不是能確保 alignment?
> 2. 如果真的會 misalign 也未必是問題, 只要他的強的程度不夠強就可以, 但要怎麼定義「強不強」呢?
>
> 這兩個問題好像有點難, 但感覺可以分開來討論。

**小節 · 討論**

兩個問題確實可以分開, 而且 Anthropic 的第一個哲學 move 就是**決定要 operationally gate 在哪一個**:

| | Q1 方向 · 測 alignment | Q2 方向 · 測 capability |
|---|---|---|
| 可測性 | 今天**不可測** — 沒有 ground truth, behavioral test 可被 gaming | 今天**可測** — 可以 benchmark, 有 operational 標準 |
| Ship 決策 | 永遠 stuck (confidence 永遠不 100%) | 有可執行標準 |
| 評價 | 理論完美, 但無法 deploy | 不完美, 但「低能力 misalignment ≠ catastrophic」所以 coverage 夠 |

Anthropic 選 Q2 — **gate 在 capability, alignment 降級為長期研究 bet**, 不是 ship 決策的 gate。

:::card{label="💡 INSIGHT" color="green"}
**注意 CK 的 phrasing**: 你寫的是「人類是不是能**確保** alignment」— 這個「是不是能確保」指向 **epistemic access** (我們能不能*知道*), 不是 alignment 本身存不存在。這個區分在 Anthropic 內部有個正式名字叫 **Scalable Oversight** — 也是他們公開承認還沒解決的 open problem。Stage 2.4 會深入。
:::

---

### Q2 — Capability 要怎麼分類? 怎麼測?

**CK 的直覺:**

> Capability 要怎麼分啊, 好難喔 XD 完全不知道怎麼拆解 XDDD
>
> 1. 簡單想法的確是可以訂一堆 metric 或 benchmark — 但這件事準不準我覺得很難說
> 2. 感覺應該是要拆解成幾個類別, 但我目前沒什麼想法要怎麼拆類別或要怎麼 metrics

**小節 · Unstick Move**

**卡住的 root cause**: 從「capability 本身」往下拆 — 但 capability 是無底的 (「聰明」怎麼定義?), 就算分好類, validity 又會變成 Q1 的問題 (metric 準不準)。

**方向 reframe** — 不從「怎麼分類 capability」出發, 從「**我怕什麼 harm**」倒推回去:

> "一個模型要有什麼能力, 才會 cause 這種 harm 到 catastrophic 程度?"

Stage 2.1 推出的 3 lens 到這裡才真正 pay off。對每個 lens 都可以倒推出「需要的 capability」。這個方向有三個好處:

- 不用定義 "general capability" (無底) — 只要定義**特定 dangerous capability** (有底)
- validity 問題變小 — 「能不能 uplift bioweapon synthesis」比「有多強」可測太多
- 類別不是硬分的, 是 **harm vector 自然 partition** 出來的

**關於你的「metric 準不準」擔心**: Anthropic 實務**不做**一個大 "danger score 0-100", 而是做很多**狹窄的 task-based eval**, 每個綁具體 harm vector。失敗模式明確: false negative (漏 danger) ≫ false positive (過度謹慎)。

---

### Q3 — 挑一個 lens 練習 — 倒推 capability category

**CK 的直覺:**

> 如果 misuse ⇒ 代表駭客破壞這個世界的速度比起 safeguard 的速度還快, 那這個世界必定瓦解, 沒有信任, 只有倒退, 因為 policy 與 law 已經毫無意義。**就有點像是東西壞掉的速度比修復速度快的話就沒救了。**
>
> 我知道生化武器的比喻, 但那某種程度是因為我已經看了答案了。其他 nuclear 武器不是也是同樣問題嗎?
>
> 感覺我擔心世界會發生的重大問題也太多了吧 ——
>
> 1. 武器製造速度太過快速 > 防禦的速度: 可以是生化武器, 可以是資訊武器
> 2. 人類已經無法用任何方式辨識是 AI 還是人類的操作 — 因為這就代表 AI 已經可以完全更有效率地取代人類
> 3. AI 已經發展自給自足到不用人類的幫忙就可以直接讓自己快速 + 無止盡地進化

**小節 · 你不是擔心太多 — 你剛寫出了 RSP threshold list**

先把你直覺寫的 3 個 categories 跟 Anthropic RSP v3.1 實際的 threshold 對照:

| CK 寫的 | Anthropic RSP v3.1 threshold | 對得上嗎 |
|---|---|---|
| #1 武器製造速度 > 防禦速度 | **CBRN uplift** (bio + cyber 為主) | ✅ 對上 |
| #2 無法辨識 AI vs 人類 | 部分在 Usage Policy, 但**沒有乾淨的 RSP threshold** | 💡 CK 原創 |
| #3 AI 自給自足 + 遞迴進化 | **AI R&D-4** (能將 6 年進度壓到 1 年) | ✅ 完全對應 |

**(a) 你直覺的 framing 有正式名字 — Offense-Defense Balance**

你寫的「東西壞掉的速度比修復速度快就沒救了」— 這在 security 理論裡叫 **offense-defense balance** (Robert Jervis, 1978)。核心命題: offense 跟 defense 的相對成本決定一個領域穩不穩。LLM 對每個 harm 的**淨效應不一樣**:

- **Bio**: 推向 offense-favoring (offensive knowledge 降, defensive infra 動不了)
- **Cyber**: 極度 offense-favoring (攻擊生成 vs 偵測)
- **Nuclear**: 幾乎中性 (LLM 兩邊都幫不上)

**(b)「Nuclear 不也是嗎?」— Bottleneck Analysis 是答案**

關鍵 framing: **LLM 有沒有 meaningful 降低某個 harm 的瓶頸**。

| 武器類別 | 主要 bottleneck | LLM 能降低嗎? | RSP gate 這裡嗎? |
|---|---|---|---|
| Nuclear | Uranium enrichment + 精密機械 (物理 / 供應鏈) | ❌ 基本不能 | Not primary |
| Bio | 合成路徑知識 + 部分 wet lab | ✅ 大幅降低 | ✅ CBRN threshold 核心 |
| Cyber | 純 information 問題 | ✅ 最大化降低 | ✅ 也在 CBRN 範疇 |

所以**不是「bio 比 nuke 危險」**, 而是**「LLM 在 bio/cyber 是關鍵 bottleneck 的移除者, 在 nuke 不是」**。Anthropic gate 的是「LLM 推動的 harm」, 不是「harm 的最終大小」。核武問題歸防核擴散條約 + IAEA 管, 不歸 LLM lab。

---

### Q4 — 觸發 threshold 了 — 然後怎麼辦?

**CK 的直覺:**

> 當然先不要 ship 啊!
>
> 然後先裝足夠的 safeguard — 當然這就會是**我怎麼知道夠不夠 → 當然不知道** — 所以才有下面的 beta testing 的想法。
>
> 如果可以的話也可以試試看能不能 gradually rolling out (有點像是 ramping 的概念) — 例如先不要 open to public 但有個 beta test。**只要還有機會 rollback 或 close gate 就還是可以接受的 rollout, 即使我們已經知道足夠危險。**
>
> 如果真的真的沒救, 我也不知道, 好像只能放棄了嗎 XDDD
>
> 或者可以 — AI 夠強說不定可以請 AI 幫助 AI 自己的研究, 說不定成長速度就足夠快速了? 人類打不過就讓 AI 自己打架 (X)。雖然最終人類有可能被犧牲, 但比起什麼都不做好多了!?

**小節 · 你一句話推出 4 個 Anthropic 實務 design**

| CK 說的 | Anthropic 對應 |
|---|---|
| 「先不要 ship, 先裝 safeguard」 | RSP gate (能力觸發 → safeguard 先到位才 deploy) |
| 「Gradually rolling out / beta / ramping」 | Staged deployment / Tiered access / Trusted Tester |
| 「還有機會 rollback 就可以接受」 | RSP **保留暫停開發權** (meta-commitment) |
| 「AI 幫 AI 研究」 | 3-track 的 Alignment Capabilities track |

**(a)「只要還有機會 rollback 就還是可以接受」— 最深的一句**

這句話的設計哲學叫 **reversibility as design constraint**:

- 你**沒辦法 ahead-of-time 證明 safeguard 夠** (Q1 已經講過 alignment 測不準)
- 退而求其次: **不證明安全, 保證「出事後能撤」**
- rollback / pause / close gate 是 **first-class feature**, 不是 emergency hack

> "we remain free to take measures such as **pausing development** ... in any circumstances we deem appropriate."
>
> — Anthropic, RSP v3.1 · reservation of pause authority

重點**不是**「承諾什麼時候會停」, 而是**「承諾始終保留『停』這個選項」**。**承諾一個 disposition, 不是承諾一個 metric**。

**(b)「AI 幫 AI research」有 recursive 陷阱 (Stage 2.4 會深入)**

你說「AI 夠強說不定可以請 AI 幫助 AI 自己的研究」— 這就是 Anthropic 3-track 裡 **Alignment Capabilities** track 的核心 bet (Dario *Machines of Loving Grace* 明講)。但有 recursive 陷阱:

> "如果你用來幫你 alignment research 的 AI 自己就 subtly misaligned 呢? 你怎麼知道它給你的 insight 不是為 future takeover 鋪路?"

這是 Stage 2.4 的 open problem。你面試能主動點出這個陷阱 = 展示你不是 naive 樂觀派的 signal。

:::card{label="⚠️ 紅旗 · 需要 REFRAME" color="amber"}
**你寫的「人類有可能被犧牲」** — 底層 reasoning 正確 (什麼都不做 ≠ 風險消失), 但 framing 在 Anthropic cultural fit 面試會被扣分 (聽起來像 utilitarian trolley problem)。

**安全版 (等價邏輯, 避開紅旗)**:

> 「我不認為 Anthropic 在做 'sacrifice humans for progress' 的賭注。不建 ≠ 風險消失, 只是把 frontier 留給 capability-first labs。Anthropic 的 bet 是 **asymmetric expected value**: 讓把 safety 當 operational priority 的 lab 走在前面, 比全部 capability-first labs 定義 frontier 好。」

這叫 **race-to-the-top**, 是 Anthropic 公開立場。同樣的 reasoning, framing 換了就從紅旗變成 L3+ signal。
:::

---

### Q5 — Discrete levels 還是 continuous risk score?

**CK 的直覺:**

> 我還沒有理解到我要怎麼分類吧 — 或者其實也不用, 反正大家分類方式不一樣。在面試的時候, 我知道現在的 ASL 分類方式是 Anthropic「選擇」的就足夠好了。

**小節 · Stance 成熟, 但補一個 design choice**

Stance 對了一半 — 具體 threshold 數字 (AI R&D-4 怎麼定義) 的確是 trivia 層級, 不用死背。但**「為什麼選 discrete levels 而不是 continuous risk score」**這個 design choice 本身有 signal, 要會講。

| | Continuous (0-100 score) | Discrete (ASL-2/3/4) |
|---|---|---|
| 精度 | 高 | 低 |
| 邊界 | 平滑 | 武斷 |
| Pre-commitment 強度 | 弱 (永遠可以「recalibrate」) | **強** (超過 threshold = 整包 safeguard 必須到位) |
| 對外溝通 | 難 (risk score 74.3 沒人聽得懂) | 易 (「Level 3」可以上新聞) |

:::card{label="💡 關鍵 INSIGHT" color="green"}
**Ulysses Contract**

**Discrete threshold 是 commitment device, 不是 measurement precision claim.**

像飲酒年齡 21 歲 — 不是宣稱「20.99 → 21.01 有本質差異」, 是**為了 enforcement 存在的硬線**。ASL 同理 — 強迫 Anthropic 未來的自己無法 soft-excuse 決策。這是 **Ulysses contract**: 用 pre-commitment 約束 future self, 防止 future weakness。
:::

:::fold 補充閱讀 · Ulysses Contract 的數學 framing
在 commitment theory 裡, 一個 rational agent 在 t₀ 知道自己在 t₁ 會面對誘惑, 理性做法是在 t₀ 自綁。設決策函數為 f: State → Action, 定義 commitment device 為投影 π_C: f → f' 使得 f' 在 constraint C 上有嚴格約束 (某些 state 下的 action 被禁止)。

ASL 就是這樣一個 π_C: 從「有 wiggle room 的判斷函數」投影到「capability threshold 觸發 → safeguard 必須到位」的硬線函數。trade-off 是 f' 比 f 在某些 state 下有 suboptimal 的 action (太保守), 但換到對 future weakness 的 robustness。

這個折疊區內容是選讀 — 不影響你面試表現, 但如果你對 pre-commitment theory 有興趣可以延伸到 Strotz (1956) 的 time-inconsistency 論文。
:::

---

:::card{label="🏛 ANTHROPIC'S INSTANTIATION" color="amber"}
## Anthropic 實際 Instantiation

當理解上面五個問題的思考過程後, 下面是 Anthropic 實際整理出來的視角與具體 instantiation。CK 推出來的 7 條 core principles (下一區對照表會整理), 這一區是**從骨架走到具體怎麼長**。

### ASL 三個 Level (現行 RSP v3.1)

**ASL-2 — 現役基線**. 所有 production Claude 的 default。Safeguard = Usage Policy + 基本 monitoring + Trust & Safety review。模型有 persuasion / cyberattack uplift / bio research assistance 等能力, 但不足以構成嚴重系統性危害。

**ASL-3 — 高風險能力**. Trigger (任一觸發即升級): **CBRN uplift** (對中等資源國家級計畫提供實質生化武器協助) *或* **AI R&D-4** (能將 6 年進度壓到 1 年)。觸發後 deployment **必須**先部署四層防禦, 否則不能出貨。

**ASL-4+ — 保留但未定義**. 超越人類所有認知的假設層。Anthropic 明文「threshold 尚未定義」— 這個**誠實承認**本身就是 learning organization signal, 不是漏洞。等接近 ASL-4 邊界再精確定義, 避免現在 pre-commit 未來的決策空間。

### ASL-3 觸發後的四層 Deployment 防禦

Defense in Depth 哲學: 每層 fail mode 不重疊, 不假設任一層萬無一失。

| Layer | 名稱 | 功能 |
|---|---|---|
| Layer 1 · Preventive | Access Controls | 誰能 access · pre-request gate · KYC / account auth / known adversary list · 擋「身份不對的人」 |
| Layer 2 · Real-time | Real-time Classifiers | Prompt + completion 內容層級 inline 攔截 · latency 敏感 · 擋「身份對但 request 有問題」 |
| Layer 3 · Async | Asynchronous Monitoring | 背景跑 aggregate pattern 分析 · 大模型二次審查 · 擋「單 request OK 但 cumulative pattern 有問題」 |
| Layer 4 · Post-hoc | Jailbreak Detection + Rapid Response | 事後 forensic · novel jailbreak pattern 偵測 · hours-to-days 內 patch · 擋「前三層都繞過才發現」 |

### RSP 版本演化 (learning organization 信號)

- **v1.0 · 2023-09-19** — 第一版 · ASL 架構初步定義 · 提出 capability-based gating 的哲學
- **v2.0 · 2024-10-15** — 加入具體 capability threshold definitions · 首次明確化 CBRN uplift + AI R&D 的評估方式
- **v3.1 · 2026-04-02** — 四層 deployment 防禦明文化 · AI R&D-4 threshold 正式加入 · ASL-4+ 保留但公開承認 threshold 尚未定義

每版 changelog 公開 — 框架本身在修自己, 不是一次定案。這本身就是「誠實面對自己 framework 的 limitation」的 signal, 不是 PR stunt。
:::

---

## 📊 CK's Framework vs Anthropic 實際 · 對照表

把 CK 這輪推出的 **7 條 first-principle** 擺出來, 對照 Anthropic 實際 RSP:

| # | CK's first-principle | Anthropic 實際 instantiation | 狀態 |
|---|---|---|---|
| 1 | Gate 在 capability, 不 gate 在 alignment | RSP capability threshold · Alignment → 3-track research | ✅ 完全對應 |
| 2 | Capability categories 從 harm vector 倒推, 不從 capability 正推 | CBRN + AI R&D-4 + (identity gap 歸 Usage Policy) | ✅ 2/3 · 💡 identity gap |
| 3 | Bottleneck analysis — LLM 只 gate 能 meaningful 影響的 harm | 實務一致 (為什麼 bio 不是 nuke), 但官方文件沒明說 | 💡 CK 更 sharp |
| 4 | 觸發 → staged rollout + reversibility first-class | ASL-3 部署四層防禦 + pause 權力 + staged access | ✅ · 🔧 具體四層 spec |
| 5 | Reversibility 是 disposition, 不是 metric | RSP 保留暫停權原文 ("remain free to pause") | ✅ 完全對應 |
| 6 | AI 幫 AI research, 有 recursive 陷阱 | 3-track Alignment Capabilities + Stage 2.4 open problem | ✅ 完全對應 |
| 7 | Discrete levels 是 commitment device, 非 precision claim | ASL-2/3/4 + v1.0→v3.1 演化 | ✅ · 🔧 具體切法 |

### 三區解讀

:::card{color="green"}
**✅ 對得上 (confidence booster)**

- Gate 在 capability
- Reversibility as disposition
- Staged rollout + pause 權力
- AI 幫 AI + recursive 陷阱
- Discrete = commitment device

*面試時 Anthropic 任何一條, 你都能從第一原理推出來, 不是背。*
:::

:::card{color="amber"}
**🔧 Anthropic 做的更細 (要補)**

- 四層 deployment 防禦的具體設計
- ASL 具體 level 切法
- RSP v1.0 → v3.1 演化歷程

*不用背 threshold 數字, 但要知道結構。面試現場會引用。*
:::

:::card{color="purple"}
**💡 你推得更 sharp (面試武器)**

- **Identity gap**: Anthropic RSP 沒乾淨 threshold-ify
- **Offense-defense balance**: 援引 Jervis 理論
- **Bottleneck analysis**: 顯式解釋 bio vs nuke

*這是主動表達你想過 RSP 邊界的 signal。L3+ 格。*
:::

---

## 🎤 面試現場用得上的 3 句 Pivot

面試官不會問「什麼是 ASL-3」(google-able trivia), 會問需要你有立場的問題。下面三個是常見情境 + 你的回答模板。

:::card{label="PIVOT 1 · BOTTLENECK" color="purple"}
### 被問:「為什麼特別關注 CBRN 而不是核武?」

*多數候選人: 解釋 CBRN 威脅大小。你: 翻轉問題, 講 LLM uplift 的 differential 而非 harm 的大小。*

> "I don't think Anthropic cares more about bio than nukes. They gate on where LLM uplift is the binding constraint — bio 和 cyber 是 LLM 能顯著降低 bottleneck 的領域, 核武主要瓶頸是物理供應鏈, LLM 降不了。所以 gate 的是 LLM 推動的 harm 的 differential, 不是 harm 的最終大小。"
:::

:::card{label="PIVOT 2 · REVERSIBILITY" color="purple"}
### 被問:「RSP 沒有法律強制力, 算什麼承諾?」

*多數候選人: 辯護 RSP 很認真 / 公關效應之類。你: 指出 RSP 的價值不在「承諾 metric」而在「承諾 disposition」。*

> "RSP 的意義不在承諾 safety level, 在始終保留暫停權。這是承諾一個 **disposition**, 不是承諾一個 metric — 不把未來決策空間 pre-commit 掉。沒有政府強制力, 但設計上強迫 Anthropic 未來的自己無法 soft-excuse 繼續 scale。這種 commitment 比任何 binding contract 更靠近 learning organization 的本質。"
:::

:::card{label="PIVOT 3 · COMMITMENT DEVICE" color="purple"}
### 被問:「ASL-2/ASL-3 邊界這麼武斷有意義嗎?」

*多數候選人: 試圖辯護邊界不武斷。你: 正面承認武斷 + 解釋為什麼武斷是 feature.*

> "邊界武斷是 feature 不是 bug。Discrete threshold 是 **commitment device** — 像飲酒年齡 21 不是 claim 20.99→21.01 有本質差異, 是 enforcement 硬線。如果是 continuous score, 永遠可以 'recalibrate' 避開 safeguard。Discrete 讓 Anthropic 沒有 wiggle room。這是 Ulysses contract — 用 pre-commitment 約束 future self。"
:::

---

:::card{label="🚦 CONCEPT-CHECK GATE" color="blue"}
## Concept-check Gate

用你自己的話回答三題 (不用回去看內文, 不用完整背原文):

> **(a)** 為什麼 Anthropic 選擇 gate 在 *capability* 而不是 *alignment*? 今天這兩個題目的「可測性」差異是什麼?
>
> **(b)** 為什麼 capability categories 要從 *harm 倒推*, 不從 capability 正推? 說出你推出的 3 個 categories 分別對應到 Anthropic 實際哪個 threshold。
>
> **(c)**「RSP 保留暫停權」跟「承諾達到某個 safety level」有什麼本質差別? 為什麼前者在沒有法律強制力下仍有意義?

:::callout
💡 這個 gate 不是背誦, 是確認你**能在面試現場即時 reason 出 capability-gated deployment 的 framework**。Anthropic 面試官會順著你的答案追問 (例如「你說的 disposition 跟 commitment 有什麼差?」), 所以你的答案必須是你自己真的能 own 的 framing, 不是模板。
:::

*Gate 狀態: 🟡 In Progress · 答完三題後會補 Passed Gate Record*
:::

---

*🐱 Rotom · AI Safety (Anthropic Cultural Fit) · Stage 2.2 · 2026-04-18*
*Generated by learning-ai-infra skill*
