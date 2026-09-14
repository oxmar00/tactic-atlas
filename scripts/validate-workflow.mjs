// Structural and routing checks for the explicitly authored response graph.
export function validateWorkflow(workflow, path = "workflow") {
 const errors=[],add=message=>errors.push(path+": "+message);
 if(!workflow||workflow.version!==1||!Array.isArray(workflow.nodes)||!Array.isArray(workflow.edges)){add("requires version 1, nodes and edges");return errors;}
 const nodes=workflow.nodes,edges=workflow.edges,byId=new Map();
 for(const n of nodes){
  if(!n||typeof n.id!=="string"||!n.id){add("node requires a stable id");continue;}
  if(byId.has(n.id))add("duplicate node "+n.id);byId.set(n.id,n);
  if(!["start","end","phase","decision","branch","escalation"].includes(n.kind))add("invalid kind "+n.id);
  if(!Number.isInteger(n.row)||n.row<0||!["spine","branch"].includes(n.column))add("invalid position "+n.id);
  if(typeof n.title!=="string"||!n.title.trim()||!Array.isArray(n.items)||n.items.some(x=>typeof x!=="string"))add("invalid text "+n.id);
 }
 const starts=nodes.filter(n=>n?.kind==="start"),ends=nodes.filter(n=>n?.kind==="end");
 if(starts.length!==1||!ends.length)add("requires one start and at least one explicit end");
 const positions=new Set();
 for(const n of nodes){const key=n?.row+"/"+n?.column;if(positions.has(key))add("two nodes occupy "+key);positions.add(key);}
 const edgeIds=new Set();
 for(const e of edges){
  const from=byId.get(e?.from),to=byId.get(e?.to);
  if(!from||!to){add("edge references a missing node");continue;}
  const key=e.from+"/"+e.to+"/"+e.label;if(edgeIds.has(key))add("duplicate edge "+key);edgeIds.add(key);
  if(!["main","branch","return"].includes(e.kind))add("invalid routing kind");
  if(e.kind==="main"&&(from.column!=="spine"||to.column!=="spine"||to.row<=from.row))add("main edge must advance down spine");
  if(e.kind==="branch"&&(from.column!=="spine"||to.column!=="branch"||from.row!==to.row))add("branch edge must share its source row");
  if(e.kind==="return"&&(from.column!=="branch"||to.column!=="spine"))add("return must rejoin spine");
 }
 for(const n of nodes){
  const outgoing=edges.filter(e=>e?.from===n?.id);
  if(n?.kind==="end"&&outgoing.length)add("end node has outgoing edges: "+n.id);
  if(n?.kind!=="end"&&!outgoing.length)add("non-end node is a dead end: "+n?.id);
  if(n?.kind==="decision"&&(outgoing.length!==2||!outgoing.some(e=>e.label==="yes")||!outgoing.some(e=>e.label==="no")))add("decision needs yes and no: "+n.id);
 }
 const walk=(seeds,reverse=false)=>{const seen=new Set(seeds);let queue=[...seeds];while(queue.length){const id=queue.shift();for(const e of edges){const a=reverse?e?.to:e?.from,b=reverse?e?.from:e?.to;if(a===id&&!seen.has(b)){seen.add(b);queue.push(b);}}}return seen;};
 if(starts.length===1){const reachable=walk([starts[0].id]);for(const n of nodes)if(!reachable.has(n?.id))add("unreachable node "+n?.id);}
 const canFinish=walk(ends.map(n=>n.id),true);
 for(const n of nodes)if(!canFinish.has(n?.id))add("no path to an explicit end: "+n?.id);
 return errors;
}
