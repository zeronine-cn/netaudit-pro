
// Risk Levels
export enum RiskLevel {
  HIGH = '高危',
  MEDIUM = '中危',
  LOW = '低危',
  SAFE = '安全'
}

// Protocols
export enum Protocol {
  TLS = 'TLS/SSL',
  SSH = 'SSH',
  DNS = 'DNS',
  HTTP = 'HTTP',
  TCP = 'TCP'
}

// Scan Modes
export enum ScanMode {
  QUICK = '快速扫描',
  DEEP = '深度审计'
}

export interface DefectDict {
  id: string;
  protocol: Protocol;
  check_item: string;
  risk_level: RiskLevel;
  description: string;
  detail_value?: string;
  suggestion: string;
  mlps_clause: string;
  metadata?: {
    success_user?: string;
    success_pass?: string;
    is_compromised?: boolean;
  };
}

export interface PortStatus {
  protocol: string;
  port: number;
  status: 'OPEN' | 'CLOSED' | 'FILTERED';
  detail: string;
}

export interface ScanReport {
  id?: number;
  target: string;
  domain?: string;
  timestamp: string;
  score: number;
  defects: DefectDict[];
  port_statuses: PortStatus[];
  summary: {
    high: number;
    medium: number;
    low: number;
  };
  // 新增：测评对象元数据
  metadata?: {
    assetName: string;
    securityLevel: string;
    location: string;
    evaluator: string;
  };
}

export interface AppConfig {
  apiBaseUrl: string;
  adminPassword?: string;
  ports: {
    ssh: string;
    http: string;
    https: string;
    dns: string;
  };
  dictionaries: {
    usernames: string;
    passwords: string;
  };
  aiConfig: {
    provider: 'gemini' | 'custom';
    baseUrl: string;
    apiKey?: string;
    model: string;
  };
}
