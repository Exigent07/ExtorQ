import { PageSkeleton } from "@/components/console/skeletons";

export default function Loading() {
  return <PageSkeleton label="system health" strip panels={3} />;
}
