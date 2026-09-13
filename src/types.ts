/**
 * UserTrack — Система мониторинга и анализа сетевых угроз
 * TypeScript Definitions for SIEM, UEBA, and IPS Modules
 */

export type UserRole = 'admin' | 'user';

export interface User {
  id: number;
  username: string;
  passwordHash: string;
  passwordPlain?: string;
  role: UserRole;
  createdAt: string;
  lastLogin?: string;
  knownIps: string[];
  fullName?: string;
  isChiefAdmin?: boolean;
}

export type EventType =
  | 'AUTH_SUCCESS'
  | 'AUTH_FAILURE'
  | 'AUTH_LOGOUT'
  | 'NETWORK_REQUEST'
  | 'PORT_ACCESS'
  | 'HONEYPOT_HIT'
  | 'API_LOG_INGEST'
  | 'ADMIN_ACCESS'
  | 'SUSPICIOUS_PROBE';

export interface NetworkEvent {
  id: number;
  timestamp: string;
  username: string;
  ipAddress: string;
  eventType: EventType;
  port: number;
  country: string;
  city: string;
  details: string;
  protocol?: 'TCP' | 'UDP' | 'HTTP' | 'HTTPS';
  payloadSnippet?: string;
}

export type IncidentSeverity = 'Low' | 'Medium' | 'High' | 'Critical';
export type IncidentStatus = 'Active' | 'Investigating' | 'Resolved';

export type IncidentType =
  | 'BRUTE_FORCE'
  | 'TIME_ANOMALY'
  | 'GEO_ANOMALY'
  | 'HONEYPOT_TRIGGER'
  | 'PORT_SCAN'
  | 'CRITICAL_PORT_ACCESS'
  | 'MALICIOUS_PAYLOAD';

export interface SecurityIncident {
  id: number;
  timestamp: string;
  incidentType: IncidentType;
  severity: IncidentSeverity;
  description: string;
  sourceIp: string;
  username?: string;
  status: IncidentStatus;
  ruleTriggered: string;
  resolvedAt?: string;
}

export interface IPBlock {
  id: number;
  ipAddress: string;
  reason: string;
  blockedAt: string;
  unlockTime: string; // ISO string
  isActive: boolean;
  blockDurationMinutes: number;
  threatActor?: string; // e.g. 'HACKER_BOT'
}

export interface HoneypotTrap {
  path: string;
  description: string;
  hitsCount: number;
  lastHitAt?: string;
}

export interface SecurityAlertNotification {
  id: string;
  timestamp: string;
  channel: 'IN_APP' | 'SYSTEM' | 'TELEGRAM';
  recipient: string;
  title: string;
  message: string;
  severity: IncidentSeverity;
  read?: boolean;
}

export interface SystemStats {
  totalEvents: number;
  totalIncidents: number;
  activeBlocks: number;
  eventsLastHour: number;
  uniqueIpsCount: number;
  threatLevel: 'Low' | 'Guarded' | 'Elevated' | 'High' | 'Severe';
}
