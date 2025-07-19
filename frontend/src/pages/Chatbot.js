import React, { useState } from 'react';
import axios from 'axios';

export default function Chatbot(){
  const [input,setInput] = useState('');
  const [messages,setMessages] = useState([
    {text:"👋 Hi! Type any South Indian food, I'll tell you its calories.", from:"bot"}
  ]);

  const handleSend = async()=>{
    if(!input.trim()) return;
    const newMessages = [...messages, {text:input,from:'user'}];
    setMessages(newMessages);
    setInput('');
    try{
      const token = localStorage.getItem('token');
      const res = await axios.post('http://localhost:5000/get-calories',
        {foodName:input},
        {headers:{Authorization:`Bearer ${token}`}}
      );
      setMessages([...newMessages,{text:res.data.message,from:'bot'}]);
    }catch(err){
      setMessages([...newMessages,{text:'❌ Error fetching data',from:'bot'}]);
    }
  }

  return(
    <div className="chat-container">
      <div className="chat-window">
        {messages.map((m,i)=>(
          <div key={i} className={m.from==='bot'?'bot-msg':'user-msg'}>
            {m.text}
          </div>
        ))}
      </div>
      <div className="chat-input">
        <input value={input} onChange={e=>setInput(e.target.value)} placeholder="Type a food name..."/>
        <button onClick={handleSend}>Send</button>
      </div>
    </div>
  );
}
