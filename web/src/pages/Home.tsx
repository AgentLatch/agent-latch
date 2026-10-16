import { Hero } from "../components/home/Hero";
import { WorkflowDiagram } from "../components/home/WorkflowDiagram";
import { CapabilitiesGrid } from "../components/home/CapabilitiesGrid";
import { GitHubStats } from "../components/home/GitHubStats";
import { VisionCallout } from "../components/home/VisionCallout";
import { OwaspSection } from "../components/home/OwaspSection";

export function Home() {
  return (
    <div className="space-y-16 sm:space-y-20">
      <Hero />
      <GitHubStats />
      <WorkflowDiagram />
      <CapabilitiesGrid />
      <OwaspSection />
      <VisionCallout />
    </div>
  );
}
