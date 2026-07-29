import { ApiProperty } from "@nestjs/swagger";
import { IsArray, ArrayNotEmpty, IsString } from "class-validator";

export class MarkManyReadDto {
  @ApiProperty({
    type: [String],
    description: "Notification IDs to mark as read",
    example: [
      "2d2ef5a1-87f7-42f8-9b6c-85f5b5ec7d19",
      "b73f61ce-f63f-4422-a769-0fc3d58c2e71",
    ],
  })
  @IsArray()
  @ArrayNotEmpty()
  @IsString({ each: true })
  ids!: string[];
}
