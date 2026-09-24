import {Canvas,useFrame} from '@react-three/fiber'
import {Float} from '@react-three/drei'
import {useMemo,useRef} from 'react'
import * as THREE from 'three'

function Shield({motionEnabled=true}){
 const group=useRef(); const ring=useRef();
 useFrame((state,delta)=>{if(!motionEnabled)return;group.current.rotation.y=THREE.MathUtils.damp(group.current.rotation.y,state.pointer.x*.22,3,delta);group.current.rotation.x=THREE.MathUtils.damp(group.current.rotation.x,-state.pointer.y*.12,3,delta);ring.current.rotation.z+=delta*.08})
 const nodes=useMemo(()=>Array.from({length:34},(_,i)=>{const a=i*2.399,r=1.12+(i%5)*.13;return [Math.cos(a)*r,Math.sin(a)*r*.8,(i%7-3)*.16]}),[])
 return <group ref={group}>
   <group ref={ring}><mesh rotation={[.8,.3,0]}><torusGeometry args={[1.5,.008,8,100]}/><meshBasicMaterial color="#18d9ff" transparent opacity={.35}/></mesh><mesh rotation={[1.2,-.4,.6]}><torusGeometry args={[1.75,.005,8,100]}/><meshBasicMaterial color="#49a8ff" transparent opacity={.23}/></mesh></group>
   <mesh position={[0,0,.05]}><shapeGeometry args={[(()=>{const s=new THREE.Shape();s.moveTo(0,1.12);s.lineTo(.76,.82);s.lineTo(.65,-.35);s.quadraticCurveTo(.38,-.86,0,-1.1);s.quadraticCurveTo(-.38,-.86,-.65,-.35);s.lineTo(-.76,.82);s.closePath();return s})()]}/><meshPhysicalMaterial color="#0c3348" metalness={.72} roughness={.23} transparent opacity={.86} side={THREE.DoubleSide}/></mesh>
   <mesh position={[0,0,.09]} scale={[.72,.8,.5]}><octahedronGeometry args={[.7,0]}/><meshBasicMaterial color="#0dd9f7" wireframe transparent opacity={.62}/></mesh>
   {nodes.map((p,i)=><group key={i} position={p}><mesh><sphereGeometry args={[i%6===0?.035:.018,10,10]}/><meshBasicMaterial color={i%3===0?'#a4f6ff':'#18bfe4'}/></mesh></group>)}
   <mesh position={[0,.05,.18]}><torusGeometry args={[.28,.035,12,48]}/><meshBasicMaterial color="#59ecff"/></mesh><mesh position={[0,-.2,.18]}><boxGeometry args={[.055,.32,.055]}/><meshBasicMaterial color="#59ecff"/></mesh>
 </group>
}
function Scene({motionEnabled}){return <Canvas fallback={<ShieldFallback/>} dpr={[1,1.5]} camera={{position:[0,0,4.1],fov:42}} gl={{alpha:true,antialias:true}}><ambientLight intensity={1.15}/><pointLight position={[3,3,4]} intensity={35} color="#20d9ff"/><pointLight position={[-3,-2,2]} intensity={16} color="#386dff"/><Float speed={motionEnabled ? 1.1 : 0} rotationIntensity={motionEnabled ? .08 : 0} floatIntensity={motionEnabled ? .18 : 0}><Shield motionEnabled={motionEnabled}/></Float></Canvas>}
function ShieldFallback(){return <div className="shield-fallback" role="img" aria-label="Cybersecurity shield visualization"><div className="fallback-orbit orbit-one"/><div className="fallback-orbit orbit-two"/><i className="fallback-node node-one"/><i className="fallback-node node-two"/><i className="fallback-node node-three"/><svg viewBox="0 0 180 205" aria-hidden="true"><path className="fallback-shield" d="M90 8 158 33v54c0 48-27 83-68 108C49 170 22 135 22 87V33L90 8Z"/><path className="fallback-shield-inner" d="M90 25 143 45v42c0 38-20 66-53 87-33-21-53-49-53-87V45l53-20Z"/><path className="fallback-lock" d="M73 92v-9a17 17 0 0 1 34 0v9m-39 0h44v37H68V92Zm22 14v9"/></svg></div>}
export default function HeroScene(){const motionEnabled=!window.matchMedia('(prefers-reduced-motion: reduce)').matches;if(!window.WebGLRenderingContext)return <ShieldFallback/>;return <div className="scene" onContextMenu={e=>e.preventDefault()}><Scene motionEnabled={motionEnabled}/></div>}
