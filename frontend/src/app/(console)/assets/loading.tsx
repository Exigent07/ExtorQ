import { PageSkeleton } from "@/components/console/skeletons";

export default function Loading() {
  return <PageSkeleton label="the asset inventory" panels={4} columns={2} />;
}
