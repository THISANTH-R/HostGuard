import React, { useCallback } from 'react';
import { ReactFlow, Background, Controls, MiniMap, useNodesState, useEdgesState, Handle, Position } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { useStore } from '../store/useStore';
import { Activity } from 'lucide-react';

const CustomNode = ({ data }: any) => {
  return (
    <div className="px-4 py-2 shadow-xl rounded-xl bg-slate-800 border border-slate-700 min-w-[150px]">
      <Handle type="target" position={Position.Top} className="w-2 h-2 !bg-indigo-500" />
      <div className="flex items-center">
        <Activity className="w-4 h-4 text-indigo-400 mr-2" />
        <div>
          <div className="text-xs font-bold text-white">{data.image}</div>
          <div className="text-[10px] text-slate-400">PID: {data.pid}</div>
        </div>
      </div>
      {data.commandline && (
        <div className="mt-2 text-[8px] text-slate-500 font-mono truncate max-w-[200px]">
          {data.commandline}
        </div>
      )}
      <Handle type="source" position={Position.Bottom} className="w-2 h-2 !bg-indigo-500" />
    </div>
  );
};

const nodeTypes = {
  custom: CustomNode,
};

export const ProcessTree = () => {
  const theme = useStore(s => s.theme);
  
  // Dummy data for now, would be fetched from API
  const initialNodes = [
    { id: '1', type: 'custom', position: { x: 250, y: 50 }, data: { image: 'explorer.exe', pid: 1024 } },
    { id: '2', type: 'custom', position: { x: 250, y: 150 }, data: { image: 'winword.exe', pid: 2048, commandline: '"C:\\Program Files\\Microsoft Office\\winword.exe" document.docx' } },
    { id: '3', type: 'custom', position: { x: 250, y: 250 }, data: { image: 'powershell.exe', pid: 4096, commandline: 'powershell.exe -enc JABz...' } }
  ];
  const initialEdges = [
    { id: 'e1-2', source: '1', target: '2', animated: true, style: { stroke: '#6366f1' } },
    { id: 'e2-3', source: '2', target: '3', animated: true, style: { stroke: '#ef4444', strokeWidth: 2 } }
  ];

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  return (
    <div className={`h-[400px] w-full rounded-2xl overflow-hidden border ${theme === 'dark' ? 'border-slate-800' : 'border-slate-200'}`}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        fitView
        className={theme === 'dark' ? 'bg-slate-900' : 'bg-slate-50'}
        colorMode={theme}
      >
        <Background gap={16} size={1} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
};
