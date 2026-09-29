import React from 'react';
import { 
  Shield, 
  Server, 
  Network, 
  Activity, 
  AlertTriangle, 
  FileText, 
  Cpu, 
  Link2, 
  Sliders, 
  Radio, 
  CheckCircle2, 
  Sparkles,
  ClipboardList,
  X
} from 'lucide-react';

interface SidebarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  isSimulatedMode: boolean;
  setIsSimulatedMode: (sim: boolean) => void;
  onRefreshReal: () => void;
  isCollecting: boolean;
  isMobileOpen?: boolean;
  onCloseMobile?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  isSimulatedMode,
  setIsSimulatedMode,
  onRefreshReal,
  isCollecting,
  isMobileOpen = false,
  onCloseMobile
}) => {
  const navItems = [
    { id: 'dashboard', label: 'SOC Dashboard', icon: Activity },
    { id: 'devices', label: 'Authorized Devices', icon: Server },
    { id: 'network', label: 'Network & Topology', icon: Network },
    { id: 'behaviour', label: 'Behavioral Baseline', icon: Sliders },
    { id: 'threats', label: 'Threat & Anomaly Detection', icon: Shield },
    { id: 'incidents', label: 'Incidents & Containment', icon: AlertTriangle },
    { id: 'predictions', label: 'Attack Forecasting (MITRE)', icon: Sparkles },
    { id: 'evidence', label: 'Blockchain Integrity', icon: Link2 },
    { id: 'audit', label: 'Audit Logs', icon: ClipboardList },
  ];

  const handleSelectTab = (id: string) => {
    setActiveTab(id);
    if (onCloseMobile) {
      onCloseMobile();
    }
  };

  const sidebarContent = (
    <div className="flex flex-col justify-between min-h-full">
      <div>
        {/* Brand Header */}
        <div className="p-6 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-600 flex items-center justify-center shadow-lg shadow-cyan-900/30">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold text-lg tracking-wider text-slate-100">SENTINEL</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800 font-mono">v1.4</span>
              </div>
              <p className="text-[11px] text-slate-400 tracking-tight">Autonomous Cyber Defense</p>
            </div>
          </div>
          {onCloseMobile && (
            <button
              onClick={onCloseMobile}
              className="lg:hidden p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800"
              aria-label="Close navigation"
            >
              <X className="w-5 h-5" />
            </button>
          )}
        </div>
        <div className="px-6 py-2 border-b border-slate-800/60 bg-slate-900/40">
          <p className="text-[10px] text-slate-400 italic">"We Don't Just Detect Threats, We Question the Assumptions."</p>
        </div>

        {/* Mode Switcher Banner */}
        <div className="p-4 mx-3 my-3 rounded-lg bg-slate-950 border border-slate-800">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold text-slate-300">TELEMETRY MODE</span>
            <span className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold ${
              isSimulatedMode ? 'bg-amber-950 text-amber-400 border border-amber-800' : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
            }`}>
              {isSimulatedMode ? 'SIMULATION' : 'REAL HARDWARE'}
            </span>
          </div>

          <div className="grid grid-cols-2 gap-2 text-xs">
            <button
              id="mode-real-btn"
              onClick={() => setIsSimulatedMode(false)}
              className={`py-1.5 px-2 rounded font-medium transition ${
                !isSimulatedMode ? 'bg-emerald-600 text-white' : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
              }`}
            >
              Real Mode
            </button>
            <button
              id="mode-sim-btn"
              onClick={() => setIsSimulatedMode(true)}
              className={`py-1.5 px-2 rounded font-medium transition ${
                isSimulatedMode ? 'bg-amber-600 text-white' : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
              }`}
            >
              Simulation
            </button>
          </div>

          {!isSimulatedMode && (
            <button
              id="harvest-collector-btn"
              onClick={onRefreshReal}
              disabled={isCollecting}
              className="w-full mt-2 py-1.5 px-2 text-xs font-medium rounded bg-cyan-700 hover:bg-cyan-600 text-white flex items-center justify-center space-x-1.5 transition disabled:opacity-50"
            >
              <Radio className={`w-3.5 h-3.5 ${isCollecting ? 'animate-pulse text-cyan-200' : ''}`} />
              <span>{isCollecting ? 'Sampling C++ Agent...' : 'Harvest Native C++'}</span>
            </button>
          )}
        </div>

        {/* Navigation Items */}
        <nav className="px-3 space-y-1 pb-4">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                id={`nav-${item.id}`}
                onClick={() => handleSelectTab(item.id)}
                className={`w-full flex items-center space-x-3 px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-slate-800 text-cyan-400 shadow-sm border border-slate-700'
                    : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                <span className="truncate">{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>

      {/* Footer Info */}
      <div className="p-4 border-t border-slate-800 text-xs text-slate-400 bg-slate-900/90 mt-auto">
        <div className="flex items-center justify-between mb-1.5">
          <span>Collector Status</span>
          <span className="flex items-center text-emerald-400 font-mono text-[11px]">
            <span className="w-2 h-2 rounded-full bg-emerald-500 mr-1.5 animate-ping"></span>
            ACTIVE (C++20)
          </span>
        </div>
        <div className="flex items-center justify-between text-[11px] text-slate-400">
          <span>Engine PID</span>
          <span className="font-mono text-slate-300">NATIVE_AGENT</span>
        </div>
      </div>
    </div>
  );

  return (
    <>
      {/* Desktop Persistent Sidebar */}
      <aside
        id="sentinel-sidebar"
        className="hidden lg:flex lg:flex-col lg:w-72 lg:flex-shrink-0 lg:sticky lg:top-0 lg:h-screen lg:overflow-y-auto bg-slate-900 border-r border-slate-800 select-none z-30"
      >
        {sidebarContent}
      </aside>

      {/* Mobile Drawer Overlay */}
      {isMobileOpen && (
        <div className="lg:hidden fixed inset-0 z-50 flex">
          <div
            className="fixed inset-0 bg-black/60 backdrop-blur-sm transition-opacity"
            onClick={onCloseMobile}
          />
          <aside
            id="sentinel-sidebar-mobile"
            className="relative w-72 max-w-[80vw] h-full bg-slate-900 border-r border-slate-800 flex flex-col select-none overflow-y-auto z-10 shadow-2xl"
          >
            {sidebarContent}
          </aside>
        </div>
      )}
    </>
  );
};

