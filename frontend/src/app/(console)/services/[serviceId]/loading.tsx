import { PageSkeleton } from "@/components/console/skeletons";

export default function Loading() {
  return <PageSkeleton label="the service" strip panels={4} columns={2} />;
}
