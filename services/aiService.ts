
import { GoogleGenAI } from "@google/genai";
import { ScanReport, AppConfig } from '../types';

/**
 * AI 审计助手：优先使用用户手动填写的密钥，确保离线和自定义配置的灵活性
 */
export const generateAIAdvice = async (report: ScanReport, aiConfig: AppConfig['aiConfig']) => {
  const hasCompromised = report.defects.some(d => d.check_item.includes('弱口令') || d.metadata?.is_compromised);

  // 根据当前 provider 获取对应的独立配置
  const provider = aiConfig.provider;
  const currentConfig = aiConfig[provider]; 

  // 密钥获取优先级：用户填写 > 环境注入
  const activeApiKey = currentConfig.apiKey || process.env.API_KEY;

  const prompt = `
    你是一名世界级的红队安全专家。请对以下资产审计报告进行深度评估：
    
    [目标资产] ${report.target}
    [安全评分] ${report.score}/100
    
    [缺陷详情]
    ${report.defects.map(d => `- [${d.risk_level}] ${d.check_item}: ${d.description} (${d.detail_value || '无额外证据数据'})`).join('\n')}
    
    ${hasCompromised ? '🚨 严重告警：检测到 SSH 弱口令爆破成功，资产已失去控制权！' : ''}
    
    请输出专业审计分析：
    1. **沦陷风险评估**：如果 SSH 爆破成功，攻击者接管系统后会进行哪些关键操作？
    2. **战术防御加固**：针对上述漏洞点，给出 3 条硬性加固指令。
    3. **等保分析**：该漏洞对等保 2.0 评测的影响。
    
    要求：语气冷峻、专业，使用 Markdown 格式。直接输出内容，不要任何开场白。
  `;

  if (provider === 'gemini') {
    try {
      if (!activeApiKey) {
        return "### ⚠️ 鉴权令牌缺失\n\nAI 专家引擎未能检测到有效的 API Key。请在 [引擎配置] 中手动填写您的密钥或确保环境变量已正确注入。";
      }

      // 构造 ClientOptions, 如果用户填了代理地址则传入 baseUrl
      const clientParams: any = { apiKey: activeApiKey };
      if (currentConfig.baseUrl && currentConfig.baseUrl.trim() !== '') {
          clientParams.baseUrl = currentConfig.baseUrl;
      }

      const ai = new GoogleGenAI(clientParams);
      const response = await ai.models.generateContent({
        model: currentConfig.model || 'gemini-3-pro-preview',
        contents: prompt,
      });
      return response.text || "AI 服务响应异常：空数据。";
    } catch (error: any) {
      console.error("Gemini 审计链路异常:", error);
      return `### ⚠️ AI 审计链路中断 (Gemini)\n\n原因: ${error.message}`;
    }
  }

  // 模式 2: 自定义 OpenAI 兼容接口
  // 使用 currentConfig 中的 baseUrl
  if (!currentConfig.baseUrl) {
     return "### ⚠️ 配置缺失\n\n自定义接口模式必须填写 [接口地址 (Endpoint)]。";
  }

  try {
    const response = await fetch(`${currentConfig.baseUrl.replace(/\/$/, "")}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${activeApiKey}`
      },
      body: JSON.stringify({
        model: currentConfig.model,
        messages: [{ role: 'user', content: prompt }],
        temperature: 0.7,
        max_tokens: 2048,
        stream: false
      })
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.error?.message || `HTTP ${response.status} 链路异常`);
    }

    const data = await response.json();
    return data.choices[0].message.content;
  } catch (error: any) {
    console.error("自定义 AI 审计异常:", error);
    return `### ⚠️ AI 审计链路中断 (Custom)\n\n端点: ${currentConfig.baseUrl}\n原因: ${error.message}`;
  }
};
