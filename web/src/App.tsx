import { Navigate, Route, Routes } from "react-router-dom";
import { PageLayout } from "./components/layout/PageLayout";
import { Dashboard } from "./pages/Dashboard";
import { Scans } from "./pages/Scans";
import { Findings } from "./pages/Findings";
import { Settings } from "./pages/Settings";

export default function App() {
  return (
    <PageLayout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/scans" element={<Scans />} />
        <Route path="/findings" element={<Findings />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </PageLayout>
  );
}
