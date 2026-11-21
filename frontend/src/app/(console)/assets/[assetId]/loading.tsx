import { PageSkeleton } from "@/components/console/skeletons";

export default function Loading() {
  return <PageSkeleton label="the asset" strip panels={3} />;
}
