import React from "react";
import ReactDOM from "react-dom/client";

import ApprovalApp from "./approval";
import "./ui.css";

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <ApprovalApp />
  </React.StrictMode>,
);
