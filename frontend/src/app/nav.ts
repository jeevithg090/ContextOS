import {
  Activity,
  BarChart3,
  Bot,
  ClipboardList,
  FileSearch,
  FlaskConical,
  GitBranch,
  History,
  KanbanSquare,
  LayoutDashboard,
  Library,
  ListChecks,
  Package,
  Plug,
  Radar,
  ScrollText,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Sparkles,
  UserCheck,
  type LucideIcon,
} from "lucide-react";

export interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  /** Short answer to "what question does this screen answer?" — shown as a tooltip. */
  question: string;
  badgeKey?: "pendingApprovals" | "openIncidents" | "openFindings";
}

export interface NavSection {
  title: string;
  items: NavItem[];
}

export const NAV: NavSection[] = [
  {
    title: "Security",
    items: [
      { to: "/", label: "Overview", icon: LayoutDashboard, question: "What is the security posture of my agents right now?" },
      { to: "/agents", label: "Agents", icon: Bot, question: "Which agents exist, what can they do and how risky are they?" },
      { to: "/context", label: "Context Explorer", icon: FileSearch, question: "What information entered my agents, and from where?" },
      { to: "/provenance", label: "Provenance Graph", icon: GitBranch, question: "How did information flow from sources to actions?" },
      { to: "/trust", label: "Trust Centre", icon: ShieldCheck, question: "Which sources and destinations do we trust, and for what?" },
      { to: "/intelligence", label: "Security Intelligence", icon: Radar, question: "What suspicious behaviour has been detected?", badgeKey: "openFindings" },
      { to: "/policies", label: "Policy Studio", icon: ScrollText, question: "What are agents allowed to do?" },
      { to: "/approvals", label: "Approval Centre", icon: UserCheck, question: "Which sensitive actions are waiting for a human?", badgeKey: "pendingApprovals" },
      { to: "/incidents", label: "Incidents", icon: Siren, question: "What needs investigating?", badgeKey: "openIncidents" },
      { to: "/replay", label: "Replay Lab", icon: History, question: "What exactly happened — and what if policy had been different?" },
      { to: "/simulation", label: "Simulation Lab", icon: FlaskConical, question: "Would our controls catch these attacks?" },
    ],
  },
  {
    title: "Engineering",
    items: [
      { to: "/work/my", label: "My Work", icon: ListChecks, question: "What am I working on?" },
      { to: "/work/boards", label: "Kanban Boards", icon: KanbanSquare, question: "Where is every piece of work?" },
      { to: "/work/tasks", label: "All Tasks", icon: ClipboardList, question: "Find any task." },
      { to: "/work/remediation", label: "Security Remediation", icon: ShieldAlert, question: "Which findings still need fixing?" },
      { to: "/work/fix-context", label: "AI Fix Context", icon: Sparkles, question: "Give a coding agent everything it needs to fix this." },
      { to: "/work/prompts", label: "Prompt Library", icon: Library, question: "Reusable fix-prompt templates and saved prompts." },
      { to: "/work/context-packs", label: "Context Packs", icon: Package, question: "What project context goes to a coding agent?" },
      { to: "/work/analytics", label: "Engineering Analytics", icon: BarChart3, question: "Are we fixing things fast enough?" },
    ],
  },
  {
    title: "Platform",
    items: [
      { to: "/integrations", label: "Integrations", icon: Plug, question: "Which agent frameworks are connected and what can they enforce?" },
      { to: "/audit", label: "Audit Log", icon: Activity, question: "Who did what, and is the record intact?" },
      { to: "/settings", label: "Settings", icon: Settings, question: "Organisation, members, API keys and preferences." },
    ],
  },
];
